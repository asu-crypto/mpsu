#pragma once

#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/AES.h>

#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include "gbf.h"
#include "utl.h"
#include "elgamal.h"
#include "simpletable.h"
#include "cuckootable.h"
#include "gc.h"
#include "mot.h"

using namespace osuCrypto;


inline void psu2_v2(std::vector<std::vector<u8>> inputSet_u8, std::vector<osuCrypto::block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls)
{
	int numThreads = 1;
	bool gc_used = true;
	// bool gc_used = false;
	int gc_sent = 0;
	int gc_recv = 0;

	Timer timer;
	timer.reset();
	auto start_online = timer.setTimePoint("start");

	u64 maxBinSize = 20;
    //PSZ18
	switch ((int)log2(inputSet_u8.size()))
	{
	case (8):
		maxBinSize = 22;
	case (12):
		maxBinSize = 23;
	case (16):
		maxBinSize = 25;
	}

	u64 tablesize = setSize * 1.27;
	AES pubHash(toBlock(12138));
	
	// ============================================   local execution   ======================================

	// protocol
	// 1.key exchange
	// Curve
	REllipticCurve curve; //(CURVE_25519)
	PRNG prng(_mm_set_epi32(19249, 4923, 234435, 1231));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	// generater g
	const auto &g = curve.getGenerator();
	// sk_i
	std::vector<std::vector<u8>> s_keys; // 32 Bytes
	// g^sk_i
	std::vector<std::vector<u8>> g_sks; // 33 Bytes, y at index[][0]

	for (u64 i = 0; i < nParties; i++)
	{
		REccNumber sk(curve);
		sk.randomize(prng);
		std::vector<u8> b(sk.sizeBytes());
		sk.toBytes(b.data());
		s_keys.push_back(b);
		std::vector<u8> c(g.sizeBytes());
		REccPoint g_sk = g * sk;
		g_sk.toBytes(c.data());
		g_sks.push_back(c);
	}
	// pk
	REccNumber sk0;
	sk0.fromBytes(s_keys[0].data());
	REccPoint pk = g * sk0; // pk

	for (u64 i = 1; i < s_keys.size(); i++)
	{
		REccNumber ski;
		ski.fromBytes(s_keys[i].data());
		pk += g * ski; // pk
	}

	std::vector<u8> pk_vec(g.sizeBytes());
	pk.toBytes(pk_vec.data());

	// partial pks
	std::vector<REccPoint> par_pks;
	REccPoint par_pk = pk;
	par_pks.push_back(pk);
	for (u64 i = 1; i < s_keys.size(); i++)
	{
		REccNumber ski;
		ski.fromBytes(s_keys[i].data());
		par_pk -= g * ski;
		par_pks.push_back(par_pk);
	}

	// AES_KEY for OPRF
	PRNG prngAES(_mm_set_epi32(123, 3434565, 234435, 23987054));
	std::vector<osuCrypto::block> AES_keys;
	for (u64 i = 0; i < nParties; i++)
	{
		AES_keys.push_back(prngAES.get<osuCrypto::block>());
	}

	PRNG prng_enc(_mm_set_epi32(4253465, 3434565, 234435, 1231));

	//-------------multi-thread part for encryption----------------
	// All the parties compute the X' = Enc(pk,X)
	// encrypt_set: setSize * 2 * 33 u8 vector
	// All the parties compute the Enc(pk,0)
	// setSize * 2 * 33 u8 vector
	std::vector<std::vector<u8>> zero_ctx(2, vector<u8>(33, 0));
	std::vector<std::vector<std::vector<u8>>> encrypt_set(inputSet_u8.size(), zero_ctx);
	vector<thread> threads(numThreads);

	u64 batch_size1 = inputSet_u8.size() / numThreads;
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set(tablesize, zero_ctx);
	std::vector<u8> zero_u8(32, 0);

	u64 batch_size2 = tablesize / numThreads;

	for (int t = 0; t < numThreads; t++)
	{
		threads[t] = std::thread([&, t]()
								 {
			if(t!=numThreads-1){
        		for (u64 i = 0; i < batch_size1; i++){	
					std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i+t*batch_size1], pk_vec, prng_enc);
					encrypt_set[i+t*batch_size1] = ciphertext;
	   			}
	   
	   			for (u64 i = 0; i < batch_size2; i++){
					std::vector<std::vector<u8>> ciphertext = encryption(zero_u8, pk_vec, prng_enc);
					encrypt_zero_set[i+t*batch_size2] = ciphertext;
	   			}
			}else{
				for (u64 i = t*batch_size1; i < inputSet_u8.size(); i++){	
					std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i], pk_vec, prng_enc);
					encrypt_set[i] = ciphertext;
	   			}
	   
	   			for (u64 i = t*batch_size2; i < tablesize; i++){
					std::vector<std::vector<u8>> ciphertext = encryption(zero_u8, pk_vec, prng_enc);
					encrypt_zero_set[i] = ciphertext;
	   			}
			} });
	}

	for (int t = 0; t < numThreads; t++)
	{
		threads[t].join();
	}

	//-----------------------------------------------------------------

	// p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V(tablesize * (nParties - 1));

	// set U
	std::vector<std::vector<u8>> set_U;
	if (myIdx == 0)
	{
		set_U = inputSet_u8;
	}

	SimpleTable simple;
	CuckooTable cuckoo;
	SimpleTable simple_new;
	CuckooTable cuckoo_new;
	// store the hashed value for ith items in X_0
	std::vector<std::vector<u64>> idx_bin(inputSet_u8.size());
	std::vector<osuCrypto::block> oprf(inputSet_u8.size());
	PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 23443115, 1234567 + myIdx));
	PRNG cuckoo_dummy(_mm_set_epi32(4253465, 3431235, 23232435, 1234567 + myIdx));
	//----------------simple hashing--------------------
	// PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 234435, 1234567 + myIdx));

	simple.init(1.27, setSize, 3);

	for (u64 i = 0; i < setSize; i++)
	{
		// simple.insertItems(inputSet_block[2 * i]);
		for (u8 j = 0; j < 3; j++)
		{
			u64 address = get_hash(inputSet_block[2 * i], j, simple.numBins);
			idx_bin[i].push_back(address);
		}

		simple.insertItems(inputSet_block[2 * i]);
		// init oprf
		oprf[i] = inputSet_block[2 * i];
	}

	simple.padGlobalItems(simple_dummy, maxBinSize);

	if (myIdx != 0)
	{
		//----------------cuckoo hashing--------------------
		cuckoo.init(1.27, setSize, 3);

		for (u64 i = 0; i < setSize; i++)
		{
			cuckoo.insertItem(inputSet_block[i * 2], i);
		}
		// cuckoo.print_table();
		// cuckoo.padGlobalItems(cuckoo_dummy);
		// cuckoo.print_table();

		cuckoo_new = cuckoo;
		//--------------------------------------------------
	}

	auto end_offline2 = timer.setTimePoint("end offline");
	// std::cout << "end of offline" << std::endl;

	// =========================== online execution ==============================================
	for (u64 round = 1; round < nParties; round++)
	{
		PRNG cuckoo_dummy(_mm_set_epi32(4253465, 3431235, 23232435 + round, 1234567 + myIdx));
		PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 23443115 + round, 1234567 + myIdx));
		if (myIdx == 0)
		{
			
			// 3c----------------- mOT --------------------------------------------------
			std::vector<std::vector<Channel>> chlsmot(2, std::vector<Channel>(2));
			chlsmot[0][1] = chls[0][round];

			// mot_batched
			std::vector<osuCrypto::block> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO("127.0.0.1", 6000 + round);

				setup_semi_honest(io, 2);

				aes_keys = mot_batched_receiver(chlsmot, simple.items, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = mot_batched_receiver_ngc_multiThreads(chlsmot, simple.items, numThreads);
			}

			// std::cout << "round: " << round << " myidx: " << myIdx << " mOT" << std::endl;
			// auto end_mot = timer.setTimePoint("end mot ");
			// 3.3 message parse & decrypt
			std::vector<osuCrypto::block> recv_aes_message_batched(10 * simple.items.size());
			chls[0][round].recv(recv_aes_message_batched.data(), recv_aes_message_batched.size());
			std::vector<osuCrypto::block> oprf_new(simple.items.size());
			std::vector<std::vector<u64>> idx_bin_new(simple.items.size());

			vector<thread> threads(numThreads);
			u64 batch_size1 = simple.items.size() / numThreads;

			for (int t = 0; t < numThreads; t++)
			{
				threads[t] = std::thread([&, t]()
										 {
				u64 start,end;
				start = t*batch_size1;
				if(t!=numThreads-1){
					end = (t+1)*batch_size1;
				}else{
					end = simple.items.size();
				}
				for (u64 i = start; i < end; i++){

					std::vector<osuCrypto::block> recv_aes_message = {recv_aes_message_batched.begin() + i * 10, recv_aes_message_batched.begin() + (i + 1) * 10};
					// decrypt
					// message decode
					AESDec decryptor(aes_keys[i]);
					osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[0]);
					std::vector<osuCrypto::block> mot_message;
					if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
					{
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
						// mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
						// mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
					}
					else
					{   
                        mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
						mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
						// mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
						// mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
						// mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
						// mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
					}

					//[2:6]ciphertext of element
					std::vector<osuCrypto::block> new_ctx_block = {mot_message.begin(), mot_message.end()};

					std::vector<std::vector<u8>> new_ctx = blocks_to_ciphertexts(new_ctx_block);
					// update set_V
					set_V[i+simple.items.size()*(round-1)] = new_ctx;
				} });
			}

			for (int t = 0; t < numThreads; t++)
			{
				threads[t].join();
			}

			// oprf.insert(oprf.end(), oprf_new.begin(), oprf_new.end());
			// idx_bin.insert(idx_bin.begin(), idx_bin_new.begin(), idx_bin_new.end());
			auto end_mot = timer.setTimePoint("oprf & mot");
			// std::cout << "end of mot"
			// 		  << "round " << round << " myidx " << myIdx << std::endl;
		}
		else if (myIdx == round)
		{

			// 3c----------------- mOT --------------------------------------------------

			std::vector<std::vector<Channel>> chlsmot(2, std::vector<Channel>(2));
			chlsmot[1][0] = chls[round][0];
			// 3.1 mot
			std::vector<std::array<osuCrypto::block, 2>> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO(nullptr, 6000 + round);
				setup_semi_honest(io, 1);
				aes_keys = mot_batched_sender(chlsmot, cuckoo.items, maxBinSize , io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = mot_batched_sender_ngc_multiThreads(chlsmot, cuckoo.items, maxBinSize, numThreads);
			}

			// message construction & encryption
			PRNG prng_ot_aes(toBlock(12345678 + myIdx));
			// message construction
			std::vector<osuCrypto::block> ot_messages_batched(cuckoo.items.size() * 10);

			vector<thread> threads(numThreads);
			u64 batch_size1 = cuckoo.items.size() / numThreads;

			for (int t = 0; t < numThreads; t++)
			{
				threads[t] = std::thread([&, t]()
            {
                u64 start, end;
                start = t * batch_size1;
                if (t != numThreads - 1)
                {
                    end = (t + 1) * batch_size1;
                }
                else
                {
                    end = cuckoo.items.size();
                }
                for (u64 i = start; i < end; i++)
                {
                    std::vector<osuCrypto::block> ot_messages;
                    // for dummy value
                    // v0
                    // AES
                    AES aes_0(aes_keys[i][0]);
                    std::vector<osuCrypto::block> v0;
                    // enc(0)
                    std::vector<osuCrypto::block> enc_zero0 = ciphertexts_to_blocks(encrypt_zero_set[i]);
                    v0.insert(v0.end(), enc_zero0.begin(), enc_zero0.end());
                    std::vector<osuCrypto::block> enc_v0(v0.size());
                    aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
                    ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());
                    // for real value
                    if (cuckoo.item_idx[i] == -1)
                    {
                        // v1
                        // AES
                        AES aes_1(aes_keys[i][1]);
                        std::vector<osuCrypto::block> v1;

                        // enc(0)
                        std::vector<osuCrypto::block> enc_zero1 = ciphertexts_to_blocks(encrypt_zero_set[i]);
                        v1.insert(v1.end(), enc_zero1.begin(), enc_zero1.end());
                        std::vector<osuCrypto::block> enc_v1(v1.size());
                        aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
                        ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());
                    }
                    else
                    {

                        // v1
                        AES aes_1(aes_keys[i][1]);
                        std::vector<osuCrypto::block> v1;

                        // Enc(x)
                        std::vector<osuCrypto::block> enc_x = ciphertexts_to_blocks(encrypt_set[cuckoo.item_idx[i]]);
                        v1.insert(v1.end(), enc_x.begin(), enc_x.end());
                        std::vector<osuCrypto::block> enc_v1(v1.size());
                        aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
                        ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());
                    }

                    // sending messages
                    // chls[round][0].send(ot_messages.data(), ot_messages.size());
                    // have it in one
                    // ot_messages_batched.insert(ot_messages_batched.end(), ot_messages.begin(), ot_messages.end());
                    std::copy(ot_messages.begin(), ot_messages.end(), ot_messages_batched.begin() + i * ot_messages.size());
                } });
			}

			for (int t = 0; t < numThreads; t++)
			{
				threads[t].join();
			}

			chls[round][0].send(ot_messages_batched.data(), ot_messages_batched.size());

			auto end_mot = timer.setTimePoint("oprf & mot");

            for (u64 party = round + 1; party < nParties; party++)
			{
                std::vector<std::vector<Channel>> chlsmot(2, std::vector<Channel>(2));
				chlsmot[0][1] = chls[round][party];

				// mot_batched
				std::vector<osuCrypto::block> aes_keys;
				if (gc_used)
				{
					emp::NetIO *io = new NetIO("127.0.0.1", 5000 + round * 20 + party);
					setup_semi_honest(io, 2);
					// std::cout << "round: " << round << " myidx: " << myIdx << " before coprf" << std::endl;
					aes_keys = mot_batched_receiver(chlsmot, simple.items, io, &gc_sent, &gc_recv);
				}
				else
				{
					aes_keys = mot_batched_receiver_ngc_multiThreads(chlsmot, simple.items, numThreads);
				}

                // 3.3 message parse & decrypt
                std::vector<osuCrypto::block> recv_aes_message_batched(10 * simple.items.size());
                chls[round][party].recv(recv_aes_message_batched.data(), recv_aes_message_batched.size());
                std::vector<osuCrypto::block> oprf_new(simple.items.size());
                std::vector<std::vector<u64>> idx_bin_new(simple.items.size());

                vector<thread> threads(numThreads);
                u64 batch_size1 = simple.items.size() / numThreads;

                std::vector<osuCrypto::block> rerand_ctx_block_all(5 * simple.items.size());


                for (int t = 0; t < numThreads; t++)
                {
                    threads[t] = std::thread([&, t]()
                                            {
                    u64 start,end;
                    start = t*batch_size1;
                    if(t!=numThreads-1){
                        end = (t+1)*batch_size1;
                    }else{
                        end = simple.items.size();
                    }
                    for (u64 i = start; i < end; i++){

                        std::vector<osuCrypto::block> recv_aes_message = {recv_aes_message_batched.begin() + i * 10, recv_aes_message_batched.begin() + (i + 1) * 10};
                        // decrypt
                        // message decode
                        AESDec decryptor(aes_keys[i]);
                        osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[0]);
                        std::vector<osuCrypto::block> mot_message;
                        if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
                        {
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
                            // mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
                            // mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
                        }
                        else
                        {   
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
                            mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
                            // mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
                            // mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
                            // mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
                            // mot_message.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
                        }

                        //[2:6]ciphertext of element
                        std::vector<osuCrypto::block> ctx_block = {mot_message.begin(), mot_message.end()};
                        // encryption set (re-randomize)
						std::vector<std::vector<u8>> recv_ctx = blocks_to_ciphertexts(ctx_block);
						std::vector<std::vector<u8>> rerand_ctx = rerandomize(recv_ctx, pk_vec);
						// std::vector<std::vector<u8>> rerand_ctx = recv_ctx;
						std::vector<osuCrypto::block> rerand_ctx_block = ciphertexts_to_blocks(rerand_ctx);
						std::copy(rerand_ctx_block.begin(), rerand_ctx_block.end(),rerand_ctx_block_all.begin()+i*rerand_ctx_block.size());
					
                    } });
                }

                for (int t = 0; t < numThreads; t++)
                {
                    threads[t].join();
                }
                
                chls[round][party].send(rerand_ctx_block_all.data(), rerand_ctx_block_all.size());

            }
			
		}
		else if (myIdx > round && myIdx < nParties)
		{
			std::vector<std::vector<Channel>> chlsmot(2, std::vector<Channel>(2));
			chlsmot[1][0] = chls[myIdx][round];
			// 3.1 mot
			std::vector<std::array<osuCrypto::block, 2>> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO(nullptr, 5000 + round * 20 + myIdx);
				setup_semi_honest(io, 1);
				aes_keys = mot_batched_sender(chlsmot, cuckoo.items, maxBinSize, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = mot_batched_sender_ngc_multiThreads(chlsmot, cuckoo.items, maxBinSize, numThreads);
			}

			// message construction & encryption
			PRNG prng_ot_aes(toBlock(12345678 + myIdx));
			// message construction
			std::vector<osuCrypto::block> ot_messages_batched(cuckoo.items.size() * 10);

			vector<thread> threads(numThreads);
			u64 batch_size1 = cuckoo.items.size() / numThreads;

			for (int t = 0; t < numThreads; t++)
			{
				threads[t] = std::thread([&, t]()
            {
                u64 start, end;
                start = t * batch_size1;
                if (t != numThreads - 1)
                {
                    end = (t + 1) * batch_size1;
                }
                else
                {
                    end = cuckoo.items.size();
                }
                for (u64 i = start; i < end; i++)
                {
                    std::vector<osuCrypto::block> ot_messages;
                    // for dummy value
                    // v0
                    // AES
                    AES aes_0(aes_keys[i][0]);
                    std::vector<osuCrypto::block> v0;
                    // enc(0)
                    std::vector<osuCrypto::block> enc_zero0 = ciphertexts_to_blocks(encrypt_zero_set[i]);
                    v0.insert(v0.end(), enc_zero0.begin(), enc_zero0.end());
                    std::vector<osuCrypto::block> enc_v0(v0.size());
                    aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
                    ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());
                    // for real value
                    if (cuckoo.item_idx[i] == -1)
                    {
                        // v1
                        // AES
                        AES aes_1(aes_keys[i][1]);
                        std::vector<osuCrypto::block> v1;

                        // enc(0)
                        std::vector<osuCrypto::block> enc_zero1 = ciphertexts_to_blocks(encrypt_zero_set[i]);
                        v1.insert(v1.end(), enc_zero1.begin(), enc_zero1.end());
                        std::vector<osuCrypto::block> enc_v1(v1.size());
                        aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
                        ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());
                    }
                    else
                    {

                        // v1
                        AES aes_1(aes_keys[i][1]);
                        std::vector<osuCrypto::block> v1;

                        // Enc(x)
                        std::vector<osuCrypto::block> enc_x = ciphertexts_to_blocks(encrypt_set[cuckoo.item_idx[i]]);
                        v1.insert(v1.end(), enc_x.begin(), enc_x.end());
                        std::vector<osuCrypto::block> enc_v1(v1.size());
                        aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
                        ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());
                    }

                    // sending messages
                    // chls[round][0].send(ot_messages.data(), ot_messages.size());
                    // have it in one
                    // ot_messages_batched.insert(ot_messages_batched.end(), ot_messages.begin(), ot_messages.end());
                    std::copy(ot_messages.begin(), ot_messages.end(), ot_messages_batched.begin() + i * ot_messages.size());
                } });
			}

			for (int t = 0; t < numThreads; t++)
			{
				threads[t].join();
			}

			chls[myIdx][round].send(ot_messages_batched.data(), ot_messages_batched.size());

            // recv rerand ctx
			std::vector<osuCrypto::block> recv_rerand_ctx_all(5 * cuckoo.items.size());
			chls[myIdx][round].recv(recv_rerand_ctx_all.data(), recv_rerand_ctx_all.size());
            //todo rerandomization


		}
	}

	std::cout << "Party " << myIdx << " ready for decrypt" << std::endl;



	std::cout << IoStream::lock;
	std::cout << " party " << myIdx << std::endl;

	// std::cout << timer << std::endl;

	double dataSent = 0, dataRecv = 0; //, Mbps = 0, MbpsRecv = 0;

	for (u64 j = 0; j < nParties; ++j)
	{
		if (j != myIdx)
		{
			dataSent += chls[myIdx][j].getTotalDataSent();
			dataRecv += chls[myIdx][j].getTotalDataRecv();
		}
	}
	std::cout << "party #" << myIdx << "\t without DS: " << ((dataSent + dataRecv + gc_sent + gc_recv) / std::pow(2.0, 21)) << " MB" << std::endl;
	// std::cout << "party #" << myIdx << "\t Comm Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB" << std::endl;
	

	std::cout << IoStream::unlock;
    dataSent = 0, dataRecv = 0; //, Mbps = 0, MbpsRecv = 0;
    // gc_sent = 0, gc_recv = 0;
	// ========================== Decrypt & Shuffle ==============================================
	// shuffle not included for now
	if (myIdx == 0)
	{
		std::vector<osuCrypto::block> set_V_block(5 * set_V.size());

		vector<thread> threads(numThreads);
		u64 batch_size1 = set_V.size() / numThreads;

		for (int t = 0; t < numThreads; t++)
		{
			threads[t] = std::thread([&, t]()
									 {
			u64 start,end;
			start = t*batch_size1;
			if(t!=numThreads-1){
				end = (t+1)*batch_size1;
			}else{
				end = set_V.size();
			}
			for (u64 i = start; i < end; i++)
			{	
				std::vector<osuCrypto::block> ctx_block = ciphertexts_to_blocks(set_V[i]);
				// set_V_block.insert(set_V_block.end(), ctx_block.begin(), ctx_block.end());
				std::copy(ctx_block.begin(),ctx_block.end(),set_V_block.begin()+i*ctx_block.size());
			} });
		}

		for (int t = 0; t < numThreads; t++)
		{
			threads[t].join();
		}

		chls[myIdx][1].send(set_V_block.data(), set_V_block.size());

		// receive from p_n
		std::vector<osuCrypto::block> recv_set_V_block(((nParties - 1) * tablesize) * 5);
		chls[0][nParties - 1].recv(recv_set_V_block.data(), recv_set_V_block.size());
		// print_block(recv_set_V_block);
		std::vector<osuCrypto::block> dec_set_V_block;
		std::vector<u8> zero(32);
		std::vector<std::vector<u8>> elements((nParties - 1) * tablesize);

		// vector<thread> threads(numThreads);
		u64 batch_size2 = (nParties - 1) * tablesize / numThreads;

		for (int t = 0; t < numThreads; t++)
		{
			threads[t] = std::thread([&, t]()
									 {
			u64 start,end;
			start = t*batch_size2;
			if(t!=numThreads-1){
				end = (t+1)*batch_size2;
			}else{
				end = (nParties - 1) * tablesize;
			}
			for (u64 i = start; i < end; i++)
			{
				std::vector<osuCrypto::block> ctx_block1 = {recv_set_V_block.begin() + 5 * i, recv_set_V_block.begin() + 5 * i + 5};
				std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
				elements[i] = decryption(ctx_u8, s_keys[0]);
				// print_u8vec(elements[i]);
			} });
		}

		for (int t = 0; t < numThreads; t++)
		{
			threads[t].join();
		}

		set_U.insert(set_U.end(), elements.begin(), elements.end());

		// std::cout << IoStream::lock;
		// std::cout << "final result: " << std::endl;
		// for (u64 i = 0; i < set_U.size(); i++)
		// {
		// 	print_u8vec(set_U[i]);
		// }
		// std::cout << IoStream::unlock;
	}
	else
	{
		std::vector<osuCrypto::block> recv_set_V_block(((nParties - 1) * tablesize) * 5);
		chls[myIdx][myIdx - 1].recv(recv_set_V_block.data(), recv_set_V_block.size());
		std::vector<osuCrypto::block> dec_set_V_block((nParties - 1) * tablesize * 5);

		PRNG prng(_mm_set_epi32(19249, 4923, 233121465, 123));
		const auto &g = curve.getGenerator();
		REccNumber r(curve);
		r.randomize(prng);

		REccPoint gr(curve);
		gr = g * r;

		// REccPoint pk(curve);
		// pk.fromBytes(pk_vec.data());
		REccPoint pkr = par_pks[myIdx] * r;

		vector<thread> threads(numThreads);
		u64 batch_size1 = (nParties - 1) * tablesize / numThreads;

		for (int t = 0; t < numThreads; t++)
		{
			threads[t] = std::thread([&, t]()
									 {
			u64 start,end;
			start = t*batch_size1;
			if(t!=numThreads-1){
				end = (t+1)*batch_size1;
			}else{
				end = (nParties - 1) * tablesize;
			}
			for (u64 i = start; i < end; i++)
			{
				std::vector<osuCrypto::block> ctx_block1 = {recv_set_V_block.begin() + 5 * i, recv_set_V_block.begin() + 5 * i + 5};
				std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
				std::vector<std::vector<u8>> ctx = partial_decryption(ctx_u8, s_keys[myIdx]);
				// std::vector<std::vector<u8>> rerand_ctx = rerandomize(ctx, pk_vec);
				std::vector<std::vector<u8>> rerand_ctx = rerandomize_o(ctx, gr, pkr);
				std::vector<osuCrypto::block> ctx_block = ciphertexts_to_blocks(ctx);
				// dec_set_V_block.insert(dec_set_V_block.end(), ctx_block.begin(), ctx_block.end());
				std::copy(ctx_block.begin(),ctx_block.end(),dec_set_V_block.begin()+i*ctx_block.size());
			} });
		}

		for (int t = 0; t < numThreads; t++)
		{
			threads[t].join();
		}

		chls[myIdx][(myIdx + 1) % nParties].send(dec_set_V_block.data(), dec_set_V_block.size());
	}

	auto end = timer.setTimePoint("decrypt & shuffle");

	std::cout << IoStream::lock;
	std::cout << " party " << myIdx << std::endl;

	std::cout << timer << std::endl;

	// double dataSent = 0, dataRecv = 0; //, Mbps = 0, MbpsRecv = 0;

	for (u64 j = 0; j < nParties; ++j)
	{
		if (j != myIdx)
		{
			dataSent += chls[myIdx][j].getTotalDataSent();
			dataRecv += chls[myIdx][j].getTotalDataRecv();
		}
	}
	std::cout << "party #" << myIdx << "\t Comm Send: " << (dataSent / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t Comm Recv: " << (dataRecv / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t GC Comm Send: " << (gc_sent / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t GC Recv Recv: " << (gc_recv / std::pow(2.0, 20)) << " MB" << std::endl;
    std::cout << "party #" << myIdx << "\t total cost: " << ((dataSent + dataRecv + gc_sent + gc_recv) / std::pow(2.0, 21)) << " MB" << std::endl;

	std::cout << IoStream::unlock;
}

inline void mpsu_v2_test()
{
	const u64 numThreads_max = std::thread::hardware_concurrency();
	std::cout << "max number of threads: " << numThreads_max << std::endl;
	// std::vector<u64> set_sizes = {1 << 8, 1 << 12, 1 << 16};
	std::vector<u64> set_sizes = {1 << 10};
	// std::vector<u64> num_parties = {3, 4, 6, 8};
	std::vector<u64> num_parties = {4};

	for (auto setSize : set_sizes)
	{
		for (auto nParties : num_parties)
		{
			for (int iteration = 0; iteration < 1; iteration++)
			{

				// Create Channels
				IOService ios(0);

				auto ip = std::string("127.0.0.1");

				std::string sessionHint = "psu";

				std::vector<std::vector<Session>> ssns(nParties, std::vector<Session>(nParties));
				std::vector<std::vector<Channel>> chls(nParties, std::vector<Channel>(nParties));

				for (u64 i = 0; i < nParties; i++)
				{
					for (u64 j = 0; j < nParties; j++)
					{
						if (i < j)
						{
							u32 port = 1100 + j * 100 + i;
							std::string serversIpAddress = ip + ':' + std::to_string(port);
							ssns[i][j].start(ios, serversIpAddress, SessionMode::Server, sessionHint);

							chls[i][j] = ssns[i][j].addChannel();
							// ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
						}
						else if (i > j)
						{
							u32 port = 1100 + i * 100 + j;
							std::string serversIpAddress = ip + ':' + std::to_string(port);
							ssns[i][j].start(ios, serversIpAddress, SessionMode::Client, sessionHint);
							chls[i][j] = ssns[i][j].addChannel();
							// ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
						}
					}
				}

				// set generation
				// first half of same elements and second half of different elements.s

				// ECC Points
				// nParties * setSize * 32 u8 vector
				std::vector<std::vector<std::vector<u8>>> inputSet_u8(nParties);
				// nParties * 2setSize  vector
				std::vector<std::vector<osuCrypto::block>> inputSet_block(nParties);

				for (u64 i = 0; i < nParties; i++)
				{
					PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
					PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
					// std::cout<<"input from party "<<i<<std::endl;
					REllipticCurve curve; //(CURVE_25519)
					// generater g
					const auto &g = curve.getGenerator();
					for (u64 j = 0; j < setSize; j++)
					{

						REccNumber num(curve);

						if (j < setSize / 2)
						{
							num.randomize(prngSame);
						}
						else
						{
							num.randomize(prngDiff);
						}
						REccPoint p = g * num;
						std::vector<u8> p_vec(g.sizeBytes());
						p.toBytes(p_vec.data());
						p_vec.erase(p_vec.begin());
						// print_u8vec(p_vec);
						inputSet_u8[i].push_back(p_vec);
						std::vector<osuCrypto::block> p_block = u8vec_to_blocks(p_vec);
						inputSet_block[i].push_back(p_block[0]);
						inputSet_block[i].push_back(p_block[1]);

						// it is safe to erase the first bit (give 2 later still generate a valid point)
						//  p_vec.erase(p_vec.begin());
						//  p_vec.insert(p_vec.begin(), 2);
						//  p.fromBytes(p_vec.data());
					}
				}
				std::cout << "================================================" << std::endl;
				std::cout << "number of parties: " << nParties << std::endl;
				std::cout << "set size: " << inputSet_u8[0].size() << std::endl;
				std::cout << "================================================" << std::endl;

				// std::cout << "number of blocks: " << inputSet_block[0].size() << std::endl;

				// thread
				std::vector<std::thread> pThrds(nParties);
				for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
				{
					pThrds[pIdx] = std::thread([&, pIdx]()
											   {
												//    psu1(inputSet_u8[pIdx], inputSet_block[pIdx], nParties, pIdx, setSize, chls);
												   psu2_v2(inputSet_u8[pIdx], inputSet_block[pIdx], nParties, pIdx, setSize, chls); 
												   });
				}

				for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
					pThrds[pIdx].join();

				// Close channels
				for (u64 i = 0; i < nParties; i++)
				{
					for (u64 j = 0; j < nParties; j++)
					{
						if (i != j)
						{
							chls[i][j].close();
						}
					}
				}

				for (u64 i = 0; i < nParties; i++)
				{
					for (u64 j = 0; j < nParties; j++)
					{
						if (i != j)
						{
							ssns[i][j].stop();
						}
					}
				}

				ios.stop();
			}
		}
	}
}
