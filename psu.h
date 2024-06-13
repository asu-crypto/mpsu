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
#include "eccConvert.h"
#include "oprf_mpsu.h"
#include "simpletable.h"
#include "cuckootable.h"
#include "gc.h"
#include "oprf_batch_mpsu.h"
#include "rpir.h"

using namespace osuCrypto;
// batched rpir
// return aes key

// MPSU

inline void psu2_multiThread(std::vector<std::vector<u8>> inputSet_u8, std::vector<osuCrypto::block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls)
{	
	int numThreads = 2;
	// bool gc_used = true;
	bool gc_used = false;
	int gc_sent = 0;
	int gc_recv = 0;

	Timer timer;
	timer.reset();
	auto start_online = timer.setTimePoint("start");

	// u64 maxBinSize = log2(inputSet_u8.size());
	u64 maxBinSize = 20;

	switch ((int)log2(inputSet_u8.size()))
	{
	case (8):
		maxBinSize = 22;
	case (12):
		maxBinSize = 23;
	case (16):
		maxBinSize = 25;
	}

	// std::cout<<maxBinSize<<std::endl;
	u64 tablesize = setSize * 1.27;
	AES pubHash(toBlock(12138));
	// std::cout << IoStream::lock;
	// std::cout << "P" << myIdx << " input" << std::endl;
	// for (u64 i = 0; i < inputSet_u8.size(); i++)
	// {
	// 	print_u8vec(inputSet_u8[i]);
	// }
	// // print_block(inputSet_block);
	// std::cout << IoStream::unlock;

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
	std::vector<std::vector<u8>> zero_ctx(2,vector<u8>(33,0)); 
	std::vector<std::vector<std::vector<u8>>> encrypt_set(inputSet_u8.size(),zero_ctx);
	vector<thread> threads(numThreads);
	
	u64 batch_size1 = inputSet_u8.size()/numThreads;
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set(tablesize,zero_ctx);
	std::vector<u8> zero_u8(32, 0);
	
	u64 batch_size2 = tablesize/numThreads;

   	for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
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
			}
	   });
   	}
	
   	for(int t = 0;t<numThreads;t++){
       threads[t].join();
   	}
	
	//-----------------------------------------------------------------



	// p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V(tablesize*(nParties-1));

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
	std::cout<<"end of offline"<<std::endl;

	// =========================== online execution ==============================================
	for (u64 round = 1; round < nParties; round++)
	{	
		PRNG cuckoo_dummy(_mm_set_epi32(4253465, 3431235, 23232435 + round, 1234567 + myIdx));
		PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 23443115 + round, 1234567 + myIdx));
		if (myIdx == 0)
		{	
			// 3a---------------- oprf --------------------------------------------------
			// chls
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[0][1] = chls[0][round];
			// re init
			simple.clear_table();
			// oprf receiver

			oprf = dh_oprf_batched_multiThreads(pubHash, u64(0), oprf, chlsoprf, setSize + (round - 1) * simple.items.size(),numThreads); // size need to fix it!!!

			for (u64 i = 0; i < oprf.size(); i++)
			{ // oprf
				// oprf[i] = dh_oprf(pubHash, curve, 0, {oprf[i]}, chlsoprf)[0];
				// hash to simple table
				for (u64 j = 0; j < idx_bin[i].size(); j++)
				{
					simple.items[idx_bin[i][j]].push_back(oprf[i]);
				}
			}
			// print_block(oprf);

			simple.padGlobalItems(simple_dummy, maxBinSize + round - 1);
			std::cout<<"end of oprf"<<"round "<<round<<" myidx "<<myIdx<<std::endl;
			// auto end_oprf = timer.setTimePoint("end oprf ");

			// 3c----------------- mOT --------------------------------------------------
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[0][1] = chls[0][round];

			// rpir_batched
			std::vector<osuCrypto::block> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO("127.0.0.1", 6000 + round);

				setup_semi_honest(io, 2);

				aes_keys = rpir_batched_receiver(chlsrpir, simple.items, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = rpir_batched_receiver_ngc_multiThreads(chlsrpir, simple.items,numThreads);
			}

			// std::cout << "round: " << round << " myidx: " << myIdx << " mOT" << std::endl;
			// auto end_rpir = timer.setTimePoint("end rpir ");
			// 3.3 message parse & decrypt
			std::vector<osuCrypto::block> recv_aes_message_batched(14 * simple.items.size());
			chls[0][round].recv(recv_aes_message_batched.data(), recv_aes_message_batched.size());
			std::vector<osuCrypto::block> oprf_new(simple.items.size());
			std::vector<std::vector<u64>> idx_bin_new(simple.items.size());

			vector<thread> threads(numThreads);
			u64 batch_size1 = simple.items.size()/numThreads;

   			for(int t = 0;t<numThreads;t++){
			threads[t] = std::thread([&,t](){
				u64 start,end;
				start = t*batch_size1;
				if(t!=numThreads-1){
					end = (t+1)*batch_size1;
				}else{
					end = simple.items.size();
				}
				for (u64 i = start; i < end; i++){
					// std::vector<osuCrypto::block> recv_aes_message(14);
					// chls[0][round].recv(recv_aes_message.data(), recv_aes_message.size());
					std::vector<osuCrypto::block> recv_aes_message = {recv_aes_message_batched.begin() + i * 14, recv_aes_message_batched.begin() + (i + 1) * 14};
					// decrypt
					// message decode
					AESDec decryptor(aes_keys[i]);
					osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[2]);
					std::vector<osuCrypto::block> rpir_message;
					if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
					{
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
					}
					else
					{
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
						rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
					}

					// received message of length 7
					// update X and V
					//[0:1]prf value

					// simple.items[i].push_back(rpir_message[0]);
					// oprf.push_back(rpir_message[0]);
					oprf_new[i] = rpir_message[0];
					// idx_bin.push_back({i});
					idx_bin_new[i] = {i};

					//[2:6]ciphertext of element
					std::vector<osuCrypto::block> new_ctx_block = {rpir_message.begin() + 2, rpir_message.end()};

					std::vector<std::vector<u8>> new_ctx = blocks_to_ciphertexts(new_ctx_block);
					// update set_V
					set_V[i+simple.items.size()*(round-1)] = new_ctx;
				}
				});
   			}
	
			for(int t = 0;t<numThreads;t++){
				threads[t].join();
			}

			
			oprf.insert(oprf.end(),oprf_new.begin(),oprf_new.end());
			idx_bin.insert(idx_bin.begin(),idx_bin_new.begin(),idx_bin_new.end());
			auto end_mot = timer.setTimePoint("oprf & mot");
			std::cout<<"end of mot"<<"round "<<round<<" myidx "<<myIdx<<std::endl;
		}
		else if (myIdx == round)
		{
			// 3a---------------- oprf --------------------------------------------------
			// chls
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[1][0] = chls[round][0];

			PRNG key_gen(toBlock(u64(135246 + myIdx)));
			std::vector<osuCrypto::block> key;
			key.push_back(key_gen.get<osuCrypto::block>());
			key.push_back(key_gen.get<osuCrypto::block>());
			// oprf sender
			// ---------------------batched oprf---------------------------
			std::vector<osuCrypto::block> a = dh_oprf_batched_multiThreads(pubHash, u64(1), key, chlsoprf, setSize + (round - 1) * simple.items.size(),numThreads);
			// ---------------------batched oprf---------------------------

			// for (u64 i = 0; i < setSize + (round - 1) * simple.items.size(); i++)
			// {
			// 	// oprf with p0
			// 	std::vector<osuCrypto::block> a = dh_oprf(pubHash, curve, 1, key, chlsoprf);
			// }
			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				// cuckoo
				cuckoo.items[i] = dh_prf({cuckoo.items[i]}, key)[0];
			}

			// auto end_oprf = timer.setTimePoint("oprf");
			std::cout<<"end of oprf"<<"round "<<round<<" myidx "<<myIdx<<std::endl;
			// 3c----------------- mOT --------------------------------------------------

			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[round][0];
			// 3.1 rpir
			std::vector<std::array<osuCrypto::block, 2>> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO(nullptr, 6000 + round);
				setup_semi_honest(io, 1);
				aes_keys = rpir_batched_sender(chlsrpir, cuckoo.items, maxBinSize + round - 1, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = rpir_batched_sender_ngc_multiThreads(chlsrpir, cuckoo.items, maxBinSize + round - 1,numThreads);
			}
			// auto end_rpir = timer.setTimePoint("end rpir");
			// std::cout << "round: " << round << " myidx: " << myIdx << " mOT" << std::endl;
			// message construction & encryption
			PRNG prng_ot_aes(toBlock(12345678 + myIdx));
			// message construction
			std::vector<osuCrypto::block> ot_messages_batched(cuckoo.items.size()*14);

			vector<thread> threads(numThreads);
			u64 batch_size1 = cuckoo.items.size()/numThreads;

   			for(int t = 0;t<numThreads;t++){
			threads[t] = std::thread([&,t](){
				u64 start,end;
				start = t*batch_size1;
				if(t!=numThreads-1){
					end = (t+1)*batch_size1;
				}else{
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
					//$
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
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
						//$
						v1.push_back(prng_ot_aes.get<osuCrypto::block>());
						v1.push_back(prng_ot_aes.get<osuCrypto::block>());
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
						// F(k,x)
						v1.push_back(inputSet_block[2 * cuckoo.item_idx[i]]);
						v1.push_back(inputSet_block[2 * cuckoo.item_idx[i] + 1]);
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
					std::copy(ot_messages.begin(), ot_messages.end(),ot_messages_batched.begin()+i*ot_messages.size());
				}

			});
   			}
	
			for(int t = 0;t<numThreads;t++){
				threads[t].join();
			}
			
			chls[round][0].send(ot_messages_batched.data(), ot_messages_batched.size());

			auto end_mot = timer.setTimePoint("oprf & mot");
			std::cout<<"end of mot"<<"round "<<round<<" myidx "<<myIdx<<std::endl;
			// 3b 3d ------------ coprf & encryption set update -------------------------
			for (u64 i = round + 1; i < nParties; i++)
			{
				std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
				chlsrpir[0][1] = chls[round][i];

				// rpir_batched
				std::vector<osuCrypto::block> aes_keys;
				if (gc_used)
				{
					emp::NetIO *io = new NetIO("127.0.0.1", 5000 + round * 20 + i);
					setup_semi_honest(io, 2);
					// std::cout << "round: " << round << " myidx: " << myIdx << " before coprf" << std::endl;
					aes_keys = rpir_batched_receiver(chlsrpir, simple.items, io, &gc_sent, &gc_recv);
				}
				else
				{
					aes_keys = rpir_batched_receiver_ngc_multiThreads(chlsrpir, simple.items,numThreads);
				}
				// auto end_rpir = timer.setTimePoint("end rpir");
				// std::cout << "round: " << round << " myidx: " << myIdx << " coprf" << std::endl;
				// message parse

				std::vector<osuCrypto::block> recv_aes_message_all(16 * simple.items.size());
				chls[round][i].recv(recv_aes_message_all.data(), recv_aes_message_all.size());

				std::vector<u8> w_vec_all(33*simple.items.size());
				std::vector<osuCrypto::block> rerand_ctx_block_all(5*simple.items.size());

				vector<thread> threads(numThreads);
				u64 batch_size2 = simple.items.size()/numThreads;

				for(int t = 0;t<numThreads;t++){
				threads[t] = std::thread([&,t](){
					u64 start,end;
					start = t*batch_size2;
					if(t!=numThreads-1){
						end = (t+1)*batch_size2;
					}else{
						end = cuckoo.items.size();
					}
					REllipticCurve curve;
					for (u64 j = start; j < end; j++)
					{	

						std::vector<osuCrypto::block> recv_aes_message = {recv_aes_message_all.begin() + j * 16, recv_aes_message_all.begin() + j * 16 + 16};
						// decrypt
						// message decode and parse
						AESDec decryptor(aes_keys[j]);
						osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[0]);
						std::vector<osuCrypto::block> point_block;
						std::vector<osuCrypto::block> ctx_block;
						if (indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
						{
							point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
							point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
							point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
						}
						else
						{

							point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
							point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
							point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[14]));
							ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[15]));
						}

						// construct point u8vec
						std::vector<u8> y(1);
						if (point_block[0] == toBlock(u64(2)))
						{
							y[0] = 2;
						}
						else if (point_block[0] == toBlock(u64(3)))
						{
							y[0] = 3;
						}

						// point
						std::vector<u8> v_vec = blocks_to_u8vec({point_block[1], point_block[2]});
						v_vec.insert(v_vec.begin(), y.begin(), y.end());

						REccPoint v(curve);

						REccNumber key_num(curve);
						//bug for this line
						v.fromBytes(v_vec.data());
						std::vector<u8> key_vec = blocks_to_u8vec(key);

						key_num.fromBytes(key_vec.data());
						// comment cout for comparision
						v = v * key_num;
						std::vector<u8> w_vec(33);
						v.toBytes(w_vec.data());
						std::copy(w_vec.begin(), w_vec.end(),w_vec_all.begin()+j*w_vec.size());
						// encryption set (re-randomize)
						std::vector<std::vector<u8>> recv_ctx = blocks_to_ciphertexts(ctx_block);
						std::vector<std::vector<u8>> rerand_ctx = rerandomize(recv_ctx, pk_vec);
						// std::vector<std::vector<u8>> rerand_ctx = recv_ctx;
						std::vector<osuCrypto::block> rerand_ctx_block = ciphertexts_to_blocks(rerand_ctx);
						std::copy(rerand_ctx_block.begin(), rerand_ctx_block.end(),rerand_ctx_block_all.begin()+j*rerand_ctx_block.size());
					}
					});
				}
		
				for(int t = 0;t<numThreads;t++){
				threads[t].join();
				}

				chls[round][i].send(w_vec_all.data(), w_vec_all.size());

				chls[round][i].send(rerand_ctx_block_all.data(), rerand_ctx_block_all.size());
				auto end_coprf = timer.setTimePoint("coprf");
			}
			std::cout<<"end of coprf"<<"round "<<round<<" myidx "<<myIdx<<std::endl;
		}
		else if (myIdx > round && myIdx < nParties)
		{
			// 3b 3d ------------ coprf & encryption set update -------------------------

			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[myIdx][round];
			// 3.1 rpir
			std::vector<std::array<osuCrypto::block, 2>> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO(nullptr, 5000 + round * 20 + myIdx);
				setup_semi_honest(io, 1);
				aes_keys = rpir_batched_sender(chlsrpir, cuckoo.items, maxBinSize, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = rpir_batched_sender_ngc_multiThreads(chlsrpir, cuckoo.items, maxBinSize,numThreads);
			}
			// auto end_rpir = timer.setTimePoint("end rpir");
			// std::cout << "round: " << round << " myidx: " << myIdx << " coprf" << std::endl;
			// message construction
			PRNG prngAlpha(_mm_set_epi32(4253465, 3434565, 234435, 1041));

			// hash aes
			osuCrypto::AES pubHash(toBlock(12138));
			std::vector<osuCrypto::block> H_q(cuckoo.items.size());
			pubHash.ecbEncBlocks(cuckoo.items.data(), cuckoo.items.size(), H_q.data());

			// compute mOT messsages
			// 6 + 14 blocks for each instance
			// 0:2  v0 random point
			// 3:7  v0 block of Encryption zero
			// 8:10  v1 h(q)^alpha
			// 11:15 v1 block of real Encryption

			PRNG prngv0(_mm_set_epi32(4212365, 3434565, 234435, 1041));
			std::vector<osuCrypto::block> mOT_messages_all(cuckoo.items.size()*16);

			vector<thread> threads(numThreads);
			u64 batch_size2 = cuckoo.items.size()/numThreads;

			for(int t = 0;t<numThreads;t++){
			threads[t] = std::thread([&,t](){
				u64 start,end;
				start = t*batch_size2;
				if(t!=numThreads-1){
					end = (t+1)*batch_size2;
				}else{
					end = cuckoo.items.size();
				}
				REllipticCurve curve;
				for (u64 i = start; i < end; i++)
				{	
					std::vector<osuCrypto::block> mOT_messages;
					// AES
					AES aes_v0(aes_keys[i][0]);
					AES aes_v1(aes_keys[i][1]);

					// --------------- v0 -------------------
					// 0:2
					REccNumber v0_num(curve);
					v0_num.randomize(prngv0);
					REccPoint v0 = g * v0_num;
					std::vector<u8> v0_vec(33);
					v0.toBytes(v0_vec.data());
					std::vector<osuCrypto::block> y0 = {toBlock(v0_vec[0])};
					v0_vec.erase(v0_vec.begin());
					std::vector<osuCrypto::block> v0_block = u8vec_to_blocks(v0_vec);
					v0_block.insert(v0_block.begin(), y0.begin(), y0.end());
					// 3:7
					std::vector<osuCrypto::block> enc_zero0 = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v0_block.insert(v0_block.end(), enc_zero0.begin(), enc_zero0.end());

					std::vector<osuCrypto::block> v0_enc(v0_block.size());

					aes_v0.ecbEncBlocks(v0_block.data(), v0_block.size(), v0_enc.data());
					mOT_messages.insert(mOT_messages.end(), v0_enc.begin(), v0_enc.end());

					// --------------- v1 -------------------
					REccNumber alpha(curve);
					alpha.randomize(prngAlpha);

					// H(q)^alpha (bug)
					REccPoint v1(curve);
					REccNumber hq(curve);

					std::vector<u8> hq_vec = block_to_u8vec(H_q[i], 32);

					hq.fromBytes(hq_vec.data());

					//comment out for comparision
					v1 = g * hq;
					// v1 = v1 * alpha;//(bug)

					std::vector<u8> v1_vec(33);
					v1.toBytes(v1_vec.data());
					// 8:10
					std::vector<osuCrypto::block> y1 = {toBlock(v1_vec[0])};
					v1_vec.erase(v1_vec.begin());
					std::vector<osuCrypto::block> v1_block = u8vec_to_blocks(v1_vec);
					v1_block.insert(v1_block.begin(), y1.begin(), y1.end());

					// 11:15
					if (cuckoo.item_idx[i] == -1) // fake
					{
						std::vector<osuCrypto::block> enc_zero1 = ciphertexts_to_blocks(encrypt_zero_set[i]);
						v1_block.insert(v1_block.end(), enc_zero1.begin(), enc_zero1.end());
					}
					else // real
					{
						std::vector<osuCrypto::block> enc_x = ciphertexts_to_blocks(encrypt_set[cuckoo.item_idx[i]]);
						v1_block.insert(v1_block.end(), enc_x.begin(), enc_x.end());
					}
					std::vector<osuCrypto::block> v1_enc(v1_block.size());
					aes_v1.ecbEncBlocks(v1_block.data(), v1_block.size(), v1_enc.data());
					mOT_messages.insert(mOT_messages.end(), v1_enc.begin(), v1_enc.end());
					std::copy(mOT_messages.begin(), mOT_messages.end(),mOT_messages_all.begin()+i*mOT_messages.size());
				}

				});
			}
		
			for(int t = 0;t<numThreads;t++){
				threads[t].join();
			}


			chls[myIdx][round].send(mOT_messages_all.data(), mOT_messages_all.size());
			// message recv
			std::vector<u8> recv_w_vec_all(33 * cuckoo.items.size());
			chls[myIdx][round].recv(recv_w_vec_all.data(), recv_w_vec_all.size());
			simple.clear_table();
			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				std::vector<u8> recv_w_vec = {recv_w_vec_all.begin() + 33 * i, recv_w_vec_all.begin() + 33 * i + 33};
				// compute the PRF(k,q)
				REccPoint w(curve);

				w.fromBytes(recv_w_vec.data());

				// w *= alpha.inverse();

				std::vector<u8> prf_vec(33);
				w.toBytes(prf_vec.data());
				prf_vec.erase(prf_vec.begin());
				// table update
				// cuckoo
				cuckoo.items[i] = u8vec_to_blocks(prf_vec)[0];
				// simple
				if (cuckoo.item_idx[i] != -1)
				{
					for (u64 idx = 0; idx < idx_bin[cuckoo.item_idx[i]].size(); idx++)
					{
						simple.items[idx_bin[cuckoo.item_idx[i]][idx]].push_back(cuckoo.items[i]);
					}
				}
			}
			simple.padGlobalItems(simple_dummy, maxBinSize);
			// set update
			// recv rerand ctx
			std::vector<osuCrypto::block> recv_rerand_ctx_all(5 * cuckoo.items.size());
			chls[myIdx][round].recv(recv_rerand_ctx_all.data(), recv_rerand_ctx_all.size());


			for(int t = 0;t<numThreads;t++){
			threads[t] = std::thread([&,t](){
				u64 start,end;
				start = t*batch_size2;
				if(t!=numThreads-1){
					end = (t+1)*batch_size2;
				}else{
					end = cuckoo.items.size();
				}
				REllipticCurve curve;
				for (u64 i = 0; i < cuckoo.items.size(); i++)
				{ // recv rerand ctx

					std::vector<osuCrypto::block> recv_rerand_ctx = {recv_rerand_ctx_all.begin() + 5 * i, recv_rerand_ctx_all.begin() + 5 * i + 5};

					std::vector<std::vector<u8>> rerand_ctx = blocks_to_ciphertexts(recv_rerand_ctx);
					if (cuckoo.item_idx[i] != -1)
					{
						encrypt_set[cuckoo.item_idx[i]] = rerand_ctx;
					}
				}
			});
			}
		
			for(int t = 0;t<numThreads;t++){
				threads[t].join();
			}
			
			auto end_coprf = timer.setTimePoint("coprf");
			std::cout<<"end of coprf"<<"round "<<round<<" myidx "<<myIdx<<std::endl;
		}
	}

	std::cout << "Party " << myIdx << " ready for decrypt" << std::endl;
	// ========================== Decrypt & Shuffle ==============================================
	// shuffle not included for now
	if (myIdx == 0)
	{
		std::vector<osuCrypto::block> set_V_block(5*set_V.size());
		
		vector<thread> threads(numThreads);
		u64 batch_size1 = set_V.size()/numThreads;

		for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
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
			}
			});
		}
		
		for(int t = 0;t<numThreads;t++){
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
		u64 batch_size2 = (nParties - 1) * tablesize/numThreads;

		for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
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
			}
			});
		}
		
		for(int t = 0;t<numThreads;t++){
			threads[t].join();
		}

		
		set_U.insert(set_U.end(),elements.begin(),elements.end());

		

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
		std::vector<osuCrypto::block> dec_set_V_block((nParties - 1) * tablesize*5);

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
		u64 batch_size1 = (nParties - 1) * tablesize/numThreads;

		for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
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
			}
			});
		}
		
		for(int t = 0;t<numThreads;t++){
			threads[t].join();
		}

		chls[myIdx][(myIdx + 1) % nParties].send(dec_set_V_block.data(), dec_set_V_block.size());
	}

	auto end = timer.setTimePoint("decrypt & shuffle");

	std::cout << IoStream::lock;
	std::cout << " party " << myIdx << std::endl;

	std::cout << timer << std::endl;

	double dataSent = 0, dataRecv = 0; //, Mbps = 0, MbpsRecv = 0;

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

	std::cout << IoStream::unlock;
}


inline void psu2(std::vector<std::vector<u8>> inputSet_u8, std::vector<osuCrypto::block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls)
{
	// bool gc_used = true;
	bool gc_used = false;
	int gc_sent = 0;
	int gc_recv = 0;

	Timer timer;
	timer.reset();
	auto start_online = timer.setTimePoint("start");

	// u64 maxBinSize = log2(inputSet_u8.size());
	u64 maxBinSize = 20;

	switch ((int)log2(inputSet_u8.size()))
	{
	case (8):
		maxBinSize = 22;
	case (12):
		maxBinSize = 23;
	case (16):
		maxBinSize = 25;
	}

	// std::cout<<maxBinSize<<std::endl;
	u64 tablesize = setSize * 1.27;
	AES pubHash(toBlock(12138));
	// std::cout << IoStream::lock;
	// std::cout << "P" << myIdx << " input" << std::endl;
	// for (u64 i = 0; i < inputSet_u8.size(); i++)
	// {
	// 	print_u8vec(inputSet_u8[i]);
	// }
	// // print_block(inputSet_block);
	// std::cout << IoStream::unlock;

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
	// All the parties compute the X' = Enc(pk,X)
	// encrypt_set: setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_set;
	for (u64 i = 0; i < inputSet_u8.size(); i++)
	{	
		// std::vector<u8> zero_u8(32, 0);
		// std::vector<std::vector<u8>> ciphertext = {zero_u8,zero_u8};
		std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i], pk_vec, prng_enc);
		encrypt_set.push_back(ciphertext);
	}
	// p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V;

	// set U
	std::vector<std::vector<u8>> set_U;
	if (myIdx == 0)
	{
		set_U = inputSet_u8;
	}

	// All the parties compute the Enc(pk,0)
	// setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set;
	for (u64 i = 0; i < 1.27 * setSize; i++)
	{
		std::vector<u8> zero_u8(32, 0);
		// std::vector<std::vector<u8>> ciphertext = {zero_u8,zero_u8};
		std::vector<std::vector<u8>> ciphertext = encryption(zero_u8, pk_vec, prng_enc);
		encrypt_zero_set.push_back(ciphertext);
	}

	SimpleTable simple;
	CuckooTable cuckoo;
	SimpleTable simple_new;
	CuckooTable cuckoo_new;
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

	// =========================== online execution ==============================================
	for (u64 round = 1; round < nParties; round++)
	{	
		PRNG cuckoo_dummy(_mm_set_epi32(4253465, 3431235, 23232435 + round, 1234567 + myIdx));
		PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 23443115 + round, 1234567 + myIdx));
		if (myIdx == 0)
		{	
			// 3a---------------- oprf --------------------------------------------------
			// chls
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[0][1] = chls[0][round];
			// re init
			simple.clear_table();
			// oprf receiver

			oprf = dh_oprf_batched(pubHash, curve, u64(0), oprf, chlsoprf, setSize + (round - 1) * simple.items.size()); // size need to fix it!!!

			for (u64 i = 0; i < oprf.size(); i++)
			{ // oprf
				// oprf[i] = dh_oprf(pubHash, curve, 0, {oprf[i]}, chlsoprf)[0];
				// hash to simple table
				for (u64 j = 0; j < idx_bin[i].size(); j++)
				{
					simple.items[idx_bin[i][j]].push_back(oprf[i]);
				}
			}
			// print_block(oprf);

			simple.padGlobalItems(simple_dummy, maxBinSize + round - 1);

			// auto end_oprf = timer.setTimePoint("end oprf ");

			// 3c----------------- mOT --------------------------------------------------
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[0][1] = chls[0][round];

			// rpir_batched
			std::vector<osuCrypto::block> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO("127.0.0.1", 6000 + round);

				setup_semi_honest(io, 2);

				aes_keys = rpir_batched_receiver(chlsrpir, simple.items, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = rpir_batched_receiver_ngc(chlsrpir, simple.items);
			}

			// std::cout << "round: " << round << " myidx: " << myIdx << " mOT" << std::endl;
			// auto end_rpir = timer.setTimePoint("end rpir ");
			// 3.3 message parse & decrypt
			std::vector<osuCrypto::block> recv_aes_message_batched(14 * simple.items.size());
			chls[0][round].recv(recv_aes_message_batched.data(), recv_aes_message_batched.size());
			for (u64 i = 0; i < simple.items.size(); i++)
			{
				// std::vector<osuCrypto::block> recv_aes_message(14);
				// chls[0][round].recv(recv_aes_message.data(), recv_aes_message.size());
				std::vector<osuCrypto::block> recv_aes_message = {recv_aes_message_batched.begin() + i * 14, recv_aes_message_batched.begin() + (i + 1) * 14};
				// decrypt
				// message decode
				AESDec decryptor(aes_keys[i]);
				osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[2]);
				std::vector<osuCrypto::block> rpir_message;
				if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
				{
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
				}
				else
				{
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
				}

				// received message of length 7
				// update X and V
				//[0:1]prf value

				// simple.items[i].push_back(rpir_message[0]);
				oprf.push_back(rpir_message[0]);
				idx_bin.push_back({i});

				//[2:6]ciphertext of element
				std::vector<osuCrypto::block> new_ctx_block = {rpir_message.begin() + 2, rpir_message.end()};

				std::vector<std::vector<u8>> new_ctx = blocks_to_ciphertexts(new_ctx_block);
				// update set_V
				set_V.push_back(new_ctx);
			}
			auto end_mot = timer.setTimePoint("oprf & mot");
		}
		else if (myIdx == round)
		{
			// 3a---------------- oprf --------------------------------------------------
			// chls
			std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
			chlsoprf[1][0] = chls[round][0];

			PRNG key_gen(toBlock(u64(135246 + myIdx)));
			std::vector<osuCrypto::block> key;
			key.push_back(key_gen.get<osuCrypto::block>());
			key.push_back(key_gen.get<osuCrypto::block>());
			// oprf sender
			// ---------------------batched oprf---------------------------
			std::vector<osuCrypto::block> a = dh_oprf_batched(pubHash, curve, u64(1), key, chlsoprf, setSize + (round - 1) * simple.items.size());
			// ---------------------batched oprf---------------------------

			// for (u64 i = 0; i < setSize + (round - 1) * simple.items.size(); i++)
			// {
			// 	// oprf with p0
			// 	std::vector<osuCrypto::block> a = dh_oprf(pubHash, curve, 1, key, chlsoprf);
			// }
			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				// cuckoo
				cuckoo.items[i] = dh_prf({cuckoo.items[i]}, key)[0];
			}

			// auto end_oprf = timer.setTimePoint("oprf");
			// 3c----------------- mOT --------------------------------------------------

			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[round][0];
			// 3.1 rpir
			std::vector<std::array<osuCrypto::block, 2>> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO(nullptr, 6000 + round);
				setup_semi_honest(io, 1);
				aes_keys = rpir_batched_sender(chlsrpir, cuckoo.items, maxBinSize + round - 1, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = rpir_batched_sender_ngc(chlsrpir, cuckoo.items, maxBinSize + round - 1);
			}
			// auto end_rpir = timer.setTimePoint("end rpir");
			// std::cout << "round: " << round << " myidx: " << myIdx << " mOT" << std::endl;
			// message construction & encryption
			PRNG prng_ot_aes(toBlock(12345678 + myIdx));
			// message construction
			std::vector<osuCrypto::block> ot_messages_batched;
			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				std::vector<osuCrypto::block> ot_messages;
				// for dummy value
				// v0
				// AES
				AES aes_0(aes_keys[i][0]);
				std::vector<osuCrypto::block> v0;
				//$
				v0.push_back(prng_ot_aes.get<osuCrypto::block>());
				v0.push_back(prng_ot_aes.get<osuCrypto::block>());
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
					//$
					v1.push_back(prng_ot_aes.get<osuCrypto::block>());
					v1.push_back(prng_ot_aes.get<osuCrypto::block>());
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
					// F(k,x)
					v1.push_back(inputSet_block[2 * cuckoo.item_idx[i]]);
					v1.push_back(inputSet_block[2 * cuckoo.item_idx[i] + 1]);
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
				ot_messages_batched.insert(ot_messages_batched.end(), ot_messages.begin(), ot_messages.end());
			}
			chls[round][0].send(ot_messages_batched.data(), ot_messages_batched.size());

			auto end_mot = timer.setTimePoint("oprf & mot");

			// 3b 3d ------------ coprf & encryption set update -------------------------
			for (u64 i = round + 1; i < nParties; i++)
			{
				std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
				chlsrpir[0][1] = chls[round][i];

				// rpir_batched
				std::vector<osuCrypto::block> aes_keys;
				if (gc_used)
				{
					emp::NetIO *io = new NetIO("127.0.0.1", 5000 + round * 20 + i);
					setup_semi_honest(io, 2);
					// std::cout << "round: " << round << " myidx: " << myIdx << " before coprf" << std::endl;
					aes_keys = rpir_batched_receiver(chlsrpir, simple.items, io, &gc_sent, &gc_recv);
				}
				else
				{
					aes_keys = rpir_batched_receiver_ngc(chlsrpir, simple.items);
				}
				// auto end_rpir = timer.setTimePoint("end rpir");
				// std::cout << "round: " << round << " myidx: " << myIdx << " coprf" << std::endl;
				// message parse

				std::vector<osuCrypto::block> recv_aes_message_all(16 * simple.items.size());
				chls[round][i].recv(recv_aes_message_all.data(), recv_aes_message_all.size());

				std::vector<u8> w_vec_all;
				std::vector<osuCrypto::block> rerand_ctx_block_all;
				for (u64 j = 0; j < simple.items.size(); j++)
				{
					std::vector<osuCrypto::block> recv_aes_message = {recv_aes_message_all.begin() + j * 16, recv_aes_message_all.begin() + j * 16 + 16};
					// decrypt
					// message decode and parse
					AESDec decryptor(aes_keys[j]);
					osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[0]);
					std::vector<osuCrypto::block> point_block;
					std::vector<osuCrypto::block> ctx_block;
					if (indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
					{
						point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
						point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
						point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
					}
					else
					{

						point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
						point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
						point_block.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[14]));
						ctx_block.push_back(decryptor.ecbDecBlock(recv_aes_message[15]));
					}

					// construct point u8vec
					std::vector<u8> y(1);
					if (point_block[0] == toBlock(u64(2)))
					{
						y[0] = 2;
					}
					else if (point_block[0] == toBlock(u64(3)))
					{
						y[0] = 3;
					}
					// point
					std::vector<u8> v_vec = blocks_to_u8vec({point_block[1], point_block[2]});
					v_vec.insert(v_vec.begin(), y.begin(), y.end());

					REccPoint v(curve);

					REccNumber key_num(curve);

					v.fromBytes(v_vec.data());

					std::vector<u8> key_vec = blocks_to_u8vec(key);

					key_num.fromBytes(key_vec.data());
					// comment cout for comparision
					v = v * key_num;
					std::vector<u8> w_vec(33);
					v.toBytes(w_vec.data());
					// print_u8vec(w_vec);
					w_vec_all.insert(w_vec_all.end(), w_vec.begin(), w_vec.end());

					// encryption set (re-randomize)
					std::vector<std::vector<u8>> recv_ctx = blocks_to_ciphertexts(ctx_block);
					std::vector<std::vector<u8>> rerand_ctx = rerandomize(recv_ctx, pk_vec);
					// std::vector<std::vector<u8>> rerand_ctx = recv_ctx;
					std::vector<osuCrypto::block> rerand_ctx_block = ciphertexts_to_blocks(rerand_ctx);

					rerand_ctx_block_all.insert(rerand_ctx_block_all.end(), rerand_ctx_block.begin(), rerand_ctx_block.end());
				}

				chls[round][i].send(w_vec_all.data(), w_vec_all.size());

				chls[round][i].send(rerand_ctx_block_all.data(), rerand_ctx_block_all.size());
				auto end_coprf = timer.setTimePoint("coprf");
			}
		}
		else if (myIdx > round && myIdx < nParties)
		{
			// 3b 3d ------------ coprf & encryption set update -------------------------

			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[myIdx][round];
			// 3.1 rpir
			std::vector<std::array<osuCrypto::block, 2>> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO(nullptr, 5000 + round * 20 + myIdx);
				setup_semi_honest(io, 1);
				aes_keys = rpir_batched_sender(chlsrpir, cuckoo.items, maxBinSize, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = rpir_batched_sender_ngc(chlsrpir, cuckoo.items, maxBinSize);
			}
			// auto end_rpir = timer.setTimePoint("end rpir");
			// std::cout << "round: " << round << " myidx: " << myIdx << " coprf" << std::endl;
			// message construction
			PRNG prngAlpha(_mm_set_epi32(4253465, 3434565, 234435, 1041));

			// hash aes
			osuCrypto::AES pubHash(toBlock(12138));
			std::vector<osuCrypto::block> H_q(cuckoo.items.size());
			pubHash.ecbEncBlocks(cuckoo.items.data(), cuckoo.items.size(), H_q.data());

			// compute mOT messsages
			// 6 + 14 blocks for each instance
			// 0:2  v0 random point
			// 3:7  v0 block of Encryption zero
			// 8:10  v1 h(q)^alpha
			// 11:15 v1 block of real Encryption

			PRNG prngv0(_mm_set_epi32(4212365, 3434565, 234435, 1041));
			std::vector<osuCrypto::block> mOT_messages;
			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				// AES
				AES aes_v0(aes_keys[i][0]);
				AES aes_v1(aes_keys[i][1]);

				// --------------- v0 -------------------
				// 0:2
				REccNumber v0_num(curve);
				v0_num.randomize(prngv0);
				REccPoint v0 = g * v0_num;
				std::vector<u8> v0_vec(33);
				v0.toBytes(v0_vec.data());
				std::vector<osuCrypto::block> y0 = {toBlock(v0_vec[0])};
				v0_vec.erase(v0_vec.begin());
				std::vector<osuCrypto::block> v0_block = u8vec_to_blocks(v0_vec);
				v0_block.insert(v0_block.begin(), y0.begin(), y0.end());
				// 3:7
				std::vector<osuCrypto::block> enc_zero0 = ciphertexts_to_blocks(encrypt_zero_set[i]);
				v0_block.insert(v0_block.end(), enc_zero0.begin(), enc_zero0.end());

				std::vector<osuCrypto::block> v0_enc(v0_block.size());

				aes_v0.ecbEncBlocks(v0_block.data(), v0_block.size(), v0_enc.data());
				mOT_messages.insert(mOT_messages.end(), v0_enc.begin(), v0_enc.end());

				// --------------- v1 -------------------
				REccNumber alpha(curve);
				alpha.randomize(prngAlpha);

				// H(q)^alpha (bug)
				REccPoint v1(curve);
				REccNumber hq(curve);

				std::vector<u8> hq_vec = block_to_u8vec(H_q[i], 32);

				hq.fromBytes(hq_vec.data());

				//comment out for comparision
				v1 = g * hq;
				// v1 = v1 * alpha;//(bug)

				std::vector<u8> v1_vec(33);
				v1.toBytes(v1_vec.data());
				// 8:10
				std::vector<osuCrypto::block> y1 = {toBlock(v1_vec[0])};
				v1_vec.erase(v1_vec.begin());
				std::vector<osuCrypto::block> v1_block = u8vec_to_blocks(v1_vec);
				v1_block.insert(v1_block.begin(), y1.begin(), y1.end());

				// 11:15
				if (cuckoo.item_idx[i] == -1) // fake
				{
					std::vector<osuCrypto::block> enc_zero1 = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v1_block.insert(v1_block.end(), enc_zero1.begin(), enc_zero1.end());
				}
				else // real
				{
					std::vector<osuCrypto::block> enc_x = ciphertexts_to_blocks(encrypt_set[cuckoo.item_idx[i]]);
					v1_block.insert(v1_block.end(), enc_x.begin(), enc_x.end());
				}
				std::vector<osuCrypto::block> v1_enc(v1_block.size());
				aes_v1.ecbEncBlocks(v1_block.data(), v1_block.size(), v1_enc.data());
				mOT_messages.insert(mOT_messages.end(), v1_enc.begin(), v1_enc.end());
			}
			chls[myIdx][round].send(mOT_messages.data(), mOT_messages.size());
			// message recv
			std::vector<u8> recv_w_vec_all(33 * cuckoo.items.size());
			chls[myIdx][round].recv(recv_w_vec_all.data(), recv_w_vec_all.size());
			simple.clear_table();
			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				std::vector<u8> recv_w_vec = {recv_w_vec_all.begin() + 33 * i, recv_w_vec_all.begin() + 33 * i + 33};
				// compute the PRF(k,q)
				REccPoint w(curve);

				w.fromBytes(recv_w_vec.data());

				// w *= alpha.inverse();

				std::vector<u8> prf_vec(33);
				w.toBytes(prf_vec.data());
				prf_vec.erase(prf_vec.begin());
				// table update
				// cuckoo
				cuckoo.items[i] = u8vec_to_blocks(prf_vec)[0];
				// simple
				if (cuckoo.item_idx[i] != -1)
				{
					for (u64 idx = 0; idx < idx_bin[cuckoo.item_idx[i]].size(); idx++)
					{
						simple.items[idx_bin[cuckoo.item_idx[i]][idx]].push_back(cuckoo.items[i]);
					}
				}
			}
			simple.padGlobalItems(simple_dummy, maxBinSize);
			// set update
			// recv rerand ctx
			std::vector<osuCrypto::block> recv_rerand_ctx_all(5 * cuckoo.items.size());
			chls[myIdx][round].recv(recv_rerand_ctx_all.data(), recv_rerand_ctx_all.size());
			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{ // recv rerand ctx

				std::vector<osuCrypto::block> recv_rerand_ctx = {recv_rerand_ctx_all.begin() + 5 * i, recv_rerand_ctx_all.begin() + 5 * i + 5};

				std::vector<std::vector<u8>> rerand_ctx = blocks_to_ciphertexts(recv_rerand_ctx);
				if (cuckoo.item_idx[i] != -1)
				{
					encrypt_set[cuckoo.item_idx[i]] = rerand_ctx;
				}
			}
			auto end_coprf = timer.setTimePoint("coprf");
		}
	}

	std::cout << "Party " << myIdx << " ready for decrypt" << std::endl;
	// ========================== Decrypt & Shuffle ==============================================
	// shuffle not included for now
	if (myIdx == 0)
	{
		std::vector<osuCrypto::block> set_V_block;

		for (u64 i = 0; i < set_V.size(); i++)
		{
			std::vector<osuCrypto::block> ctx_block = ciphertexts_to_blocks(set_V[i]);
			set_V_block.insert(set_V_block.end(), ctx_block.begin(), ctx_block.end());
		}

		chls[myIdx][1].send(set_V_block.data(), set_V_block.size());

		// receive from p_n
		std::vector<osuCrypto::block> recv_set_V_block(((nParties - 1) * tablesize) * 5);
		chls[0][nParties - 1].recv(recv_set_V_block.data(), recv_set_V_block.size());
		// print_block(recv_set_V_block);
		std::vector<osuCrypto::block> dec_set_V_block;
		std::vector<u8> zero(32);
		for (u64 i = 0; i < (nParties - 1) * tablesize; i++)
		{
			std::vector<osuCrypto::block> ctx_block1 = {recv_set_V_block.begin() + 5 * i, recv_set_V_block.begin() + 5 * i + 5};
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<u8> element = decryption(ctx_u8, s_keys[myIdx]);
			// print_u8vec(element);

			if (element != zero)
				set_U.push_back(element);
		}
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
		std::vector<osuCrypto::block> dec_set_V_block;

		PRNG prng(_mm_set_epi32(19249, 4923, 233121465, 123));
		const auto &g = curve.getGenerator();
		REccNumber r(curve);
		r.randomize(prng);

		REccPoint gr(curve);
		gr = g * r;

		// REccPoint pk(curve);
		// pk.fromBytes(pk_vec.data());
		REccPoint pkr = par_pks[myIdx] * r;

		for (u64 i = 0; i < (nParties - 1) * tablesize; i++)
		{
			std::vector<osuCrypto::block> ctx_block1 = {recv_set_V_block.begin() + 5 * i, recv_set_V_block.begin() + 5 * i + 5};
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<std::vector<u8>> ctx = partial_decryption(ctx_u8, s_keys[myIdx]);
			// std::vector<std::vector<u8>> rerand_ctx = rerandomize(ctx, pk_vec);
			std::vector<std::vector<u8>> rerand_ctx = rerandomize_o(ctx, gr, pkr);
			std::vector<osuCrypto::block> ctx_block = ciphertexts_to_blocks(ctx);
			dec_set_V_block.insert(dec_set_V_block.end(), ctx_block.begin(), ctx_block.end());
		}

		chls[myIdx][(myIdx + 1) % nParties].send(dec_set_V_block.data(), dec_set_V_block.size());
	}

	auto end = timer.setTimePoint("decrypt & shuffle");

	std::cout << IoStream::lock;
	std::cout << " party " << myIdx << std::endl;

	std::cout << timer << std::endl;

	double dataSent = 0, dataRecv = 0; //, Mbps = 0, MbpsRecv = 0;

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

	std::cout << IoStream::unlock;
}

inline void psu1_old(std::vector<std::vector<u8>> inputSet_u8, std::vector<osuCrypto::block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls)
{
	//=============================   Local Execution   ================================
	u64 maxBinSize = 20;

	switch ((int)log2(inputSet_u8.size()))
	{
	case (8):
		maxBinSize = 22;
	case (12):
		maxBinSize = 23;
	case (16):
		maxBinSize = 25;
	}
	// std::cout<<IoStream::lock;
	// std::cout<<"P"<<myIdx<<" input"<<std::endl;
	// for(u64 i = 0; i<inputSet_u8.size(); i++){
	// 	print_u8vec(inputSet_u8[i]);
	// }
	// //print_block(inputSet_block);
	// std::cout<<IoStream::unlock;

	Timer timer;
	timer.reset();
	int gc_sent = 0;
	int gc_recv = 0;
	auto start = timer.setTimePoint("start");

	// protocol
	// 1.key exchange
	// Curve
	REllipticCurve curve; //(CURVE_25519)
	PRNG prng(_mm_set_epi32(19249, 4923, 234435, 1231));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	// generater g
	const auto &g = curve.getGenerator();
	// sk
	std::vector<u8> sk_vec(g.sizeBytes() - 1); // 32 Bytes
	// g^sk
	std::vector<u8> gsk_vec(g.sizeBytes()); // 33 Bytes, y at index[][0]
	// pk
	std::vector<u8> pk_vec(g.sizeBytes());

	if (myIdx == 1)
	{
		REccNumber sk(curve);

		sk.randomize(prng);

		sk.toBytes(sk_vec.data());

		REccPoint g_sk = g * sk;
		g_sk.toBytes(gsk_vec.data());

		REccPoint pk = g_sk;

		pk.toBytes(pk_vec.data());

		// multi thread
		std::vector<std::thread> pThrds(nParties - 1);
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]()
									   {
				if(pIdx == 0){
					chls[1][0].send(pk_vec.data(), pk_vec.size());
				}else{
					chls[1][pIdx+1].send(pk_vec.data(), pk_vec.size());
				} });
		}
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();
	}
	else
	{
		chls[myIdx][1].recv(pk_vec.data(), pk_vec.size());
	}

	PRNG prng_enc(_mm_set_epi32(4253465, 3434565, 234435, 1231));

	// All the parties compute the X' = Enc(pk,X)
	// encrypt_set: setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_set;

	for (u64 i = 0; i < inputSet_u8.size(); i++)
	{
		// std::cout<<inputSet_u8[i]<<std::endl;
		// print_u8vec(pk_vec);
		std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i], pk_vec, prng_enc);
		encrypt_set.push_back(ciphertext);
	}

	// p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V;
	if (myIdx == 0)
	{
		set_V = encrypt_set;
	}
	// set U
	std::vector<std::vector<u8>> set_U;

	////All the parties compute the Enc(pk,0)
	// setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set;
	for (u64 i = 0; i < 1.27 * setSize; i++)
	{
		// std::cout<<inputSet_u8[i]<<std::endl;
		// print_u8vec(pk_vec);
		std::vector<u8> zero_u8(32, 0);
		std::vector<std::vector<u8>> ciphertext = encryption(zero_u8, pk_vec, prng_enc);
		encrypt_zero_set.push_back(ciphertext);
	}

	//=============================   End of Local Execution   ================================

	auto online = timer.setTimePoint("online_start");

	//=============================   OPRF Execution ==========================================
	if (myIdx == 0)
	{
		// 2.=============================== OPRF P_0 & P_i ==================================
		// update channel for oprf
		std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
		chlsoprf[0][1] = chls[0][1];

		std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

		oprf_value = aes_oprf(0, inputSet_block, 2 * setSize, chlsoprf, ZeroBlock);
		inputSet_block = oprf_value;
	}
	else if (myIdx == 1)
	{
		std::vector<osuCrypto::block> oprf_value;
		// AES_KEY for OPRF
		PRNG prngOPRF(_mm_set_epi32(123, 3434565, 234435, 23987054));
		std::vector<osuCrypto::block> oprf_key = {prngOPRF.get<osuCrypto::block>()};

		// multi thread
		std::vector<std::thread> pThrds(nParties - 1);
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]()
									   {
				if(pIdx == 0){
					//----------------- with P1 -----------------
					// update channel for oprf
					std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
					chlsoprf[1][0] = chls[1][0];
					oprf_value = aes_oprf(1, inputSet_block, 2 * setSize, chlsoprf, oprf_key[0]);
					inputSet_block = oprf_value;
				}else{
					//------------------ with others ----------------
					// 4.OPRF key sharing
					chls[1][pIdx+1].send(oprf_key.data(), oprf_key.size());
				} });
		}
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();
	}
	else
	{
		// 4.OPRF key sharing
		//
		std::vector<osuCrypto::block> recv_oprf_key(1);
		chls[myIdx][1].recv(recv_oprf_key.data(), recv_oprf_key.size());

		AES aes_oprf(recv_oprf_key[0]);

		std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

		aes_oprf.ecbEncBlocks(inputSet_block.data(), inputSet_block.size(), oprf_value.data());

		inputSet_block = oprf_value;
	}

	// auto oprf = timer.setTimePoint("oprf_end");
	// cuckoo and simple hashing

	u64 tablesize = 1.27 * setSize;
	SimpleTable simple;
	CuckooTable cuckoo;

	if (myIdx == 0)
	{
		//----------------simple hashing--------------------

		PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 234435, 1234567 + myIdx));

		simple.init(1.27, setSize, 3);

		for (u64 i = 0; i < setSize; i++)
		{
			simple.insertItems(inputSet_block[2 * i]);
		}

		// std::cout << "max bin size: " << simple.getMaxBinSize() << std::endl;
		//  std::cout<<IoStream::lock;
		//  simple.print_table();
		//  std::cout<<IoStream::unlock;
		simple.padGlobalItems(simple_dummy, maxBinSize);

		//--------------------------------------------------
	}
	else
	{
		//----------------cuckoo hashing--------------------
		PRNG cuckoo_dummy(_mm_set_epi32(4253465, 3434565, 23232435, 1234567 + myIdx));

		cuckoo.init(1.27, setSize, 3);
		for (u64 i = 0; i < setSize; i++)
		{
			cuckoo.insertItem(inputSet_block[2 * i], i);
		}

		// std::cout<<IoStream::lock;
		// cuckoo.print_table();
		// std::cout<<IoStream::unlock;

		cuckoo.padGlobalItems(cuckoo_dummy);

		//--------------------------------------------------
	}
	auto hash = timer.setTimePoint("hash & porf_end");
	//===============================   mOT Execution   ================================

	for (u64 round = 1; round < nParties; round++)
	{
		// P_0
		if (myIdx == 0)
		{
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[0][1] = chls[0][round];

			// rpir_batched

			emp::NetIO *io = new NetIO("127.0.0.1", 6000 + round);
			setup_semi_honest(io, 2);

			std::vector<osuCrypto::block> aes_keys = rpir_batched_receiver(chlsrpir, simple.items, io, &gc_sent, &gc_recv);

			// 3.3 message parse & decrypt

			std::vector<osuCrypto::block> rpir_message;

			for (u64 i = 0; i < simple.items.size(); i++)
			{
				std::vector<osuCrypto::block> recv_aes_message(14);

				chls[0][round].recv(recv_aes_message.data(), recv_aes_message.size());

				// std::vector<osuCrypto::block> recv_aes_message = {recv_ot_messages.begin() + i * 14, recv_ot_messages.begin() + i * 14 + 14};

				// decrypt
				// message decode
				AESDec decryptor(aes_keys[i]);
				osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[2]);
				std::vector<osuCrypto::block> rpir_message;
				if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
				{
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
				}
				else
				{
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
				}

				// received message of length 7
				// update X and V
				//[0:1]prf value

				simple.items[i].push_back(rpir_message[0]);
				//[2:6]ciphertext of element
				std::vector<osuCrypto::block> new_ctx_block = {rpir_message.begin() + 2, rpir_message.end()};
				std::vector<std::vector<u8>> new_ctx = blocks_to_ciphertexts(new_ctx_block);
				// update set_V
				set_V.push_back(new_ctx);
			}
			auto mot = timer.setTimePoint("mot_end");
		}
		else if (myIdx == round)
		{
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[round][0];
			//  rpir
			emp::NetIO *io = new NetIO(nullptr, 6000 + round);
			setup_semi_honest(io, 1);
			std::vector<std::array<osuCrypto::block, 2>> aes_keys = rpir_batched_sender(chlsrpir, cuckoo.items, maxBinSize + round - 1, io, &gc_sent, &gc_recv);

			//  message construction & encryption

			PRNG prng_ot_aes(toBlock(12345678 + myIdx));

			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				std::vector<osuCrypto::block> ot_messages;
				// for dummy value
				if (cuckoo.item_idx[i] == -1)
				{
					// v0
					// AES
					AES aes_0(aes_keys[i][0]);
					std::vector<osuCrypto::block> v0;
					//$
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero0 = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v0.insert(v0.end(), enc_zero0.begin(), enc_zero0.end());
					std::vector<osuCrypto::block> enc_v0(v0.size());
					aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
					ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());
					// v1
					// AES
					AES aes_1(aes_keys[i][1]);
					std::vector<osuCrypto::block> v1;
					//$
					v1.push_back(prng_ot_aes.get<osuCrypto::block>());
					v1.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero1 = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v1.insert(v1.end(), enc_zero1.begin(), enc_zero1.end());
					std::vector<osuCrypto::block> enc_v1(v1.size());
					aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
					ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());
				}
				// for real value
				else
				{
					// v0
					// AES
					AES aes_0(aes_keys[i][0]);
					std::vector<osuCrypto::block> v0;
					//$
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v0.insert(v0.end(), enc_zero.begin(), enc_zero.end());
					std::vector<osuCrypto::block> enc_v0(v0.size());
					aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
					ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());

					// v1
					AES aes_1(aes_keys[i][1]);
					std::vector<osuCrypto::block> v1;
					// F(k,x)
					v1.push_back(inputSet_block[2 * cuckoo.item_idx[i]]);
					v1.push_back(inputSet_block[2 * cuckoo.item_idx[i] + 1]);
					// Enc(x)
					std::vector<osuCrypto::block> enc_x = ciphertexts_to_blocks(encrypt_set[cuckoo.item_idx[i]]);
					v1.insert(v1.end(), enc_x.begin(), enc_x.end());
					std::vector<osuCrypto::block> enc_v1(v1.size());
					aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
					ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());

					// if(i == 0 && round == 1){
					// 	print_block(rpir_input);
					// 	std::cout<<"size of rpir input: "<<rpir_input.size()<<std::endl;
					// }
				}

				chls[round][0].send(ot_messages.data(), ot_messages.size());
			}
			auto mot = timer.setTimePoint("mot_end");

			// std::cout<<ot_messages.size()<<std::endl;
		}
	}

	// 5.Decrypt & shuffle
	if (myIdx == 0)
	{
		// shuffle not included for now
		// we can shuffle set_V;
		shuffle(set_V.begin(), set_V.end(), prng);

		std::vector<osuCrypto::block> set_V_block;

		for (u64 i = 0; i < set_V.size(); i++)
		{
			std::vector<osuCrypto::block> ctx_block = ciphertexts_to_blocks(set_V[i]);
			set_V_block.insert(set_V_block.end(), ctx_block.begin(), ctx_block.end());
		}
		chls[0][1].send(set_V_block.data(), set_V_block.size());
	}
	else if (myIdx == 1)
	{
		auto decrypt_start1 = timer.setTimePoint("decrypt_start1");
		std::vector<osuCrypto::block> recv_set_V_block(((nParties - 1) * tablesize + setSize) * 5);
		chls[1][0].recv(recv_set_V_block.data(), recv_set_V_block.size());
		auto decrypt_start2 = timer.setTimePoint("decrypt_start2");
		for (u64 i = 0; i < recv_set_V_block.size() / 5; i++)
		{
			std::vector<osuCrypto::block> ctx_block1 = {recv_set_V_block.begin() + 5 * i, recv_set_V_block.begin() + 5 * i + 5};
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<u8> element = decryption(ctx_u8, sk_vec);
			// print_u8vec(element);
			std::vector<u8> zero(32);
			if (element != zero)
				set_U.push_back(element);
		}
	}

	auto end = timer.setTimePoint("decrypt_end");

	std::cout << IoStream::lock;
	std::cout << " party " << myIdx << "\t" << timer << std::endl;

	double dataSent = 0, dataRecv = 0; //, Mbps = 0, MbpsRecv = 0;

	for (u64 j = 0; j < nParties; ++j)
	{
		if (j != myIdx)
		{
			dataSent += chls[myIdx][j].getTotalDataSent();
			dataRecv += chls[myIdx][j].getTotalDataRecv();
		}
	}

	std::cout << "party #" << myIdx << "\t Comm Send: " << ((dataSent) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t Comm Recv: " << ((dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t GC Comm Send: " << (gc_sent / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t GC Recv Recv: " << (gc_recv / std::pow(2.0, 20)) << " MB" << std::endl;
	// std::cout << "party #" << myIdx << "\t Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << IoStream::unlock;
}

inline void psu1(std::vector<std::vector<u8>> inputSet_u8, std::vector<osuCrypto::block> inputSet_block, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls)
{	
	// bool gc_used = true;
	bool gc_used = false;
	//=============================   Local Execution   ================================
	u64 maxBinSize = 20;

	switch ((int)log2(inputSet_u8.size()))
	{
	case (8):
		maxBinSize = 22;
	case (12):
		maxBinSize = 23;
	case (16):
		maxBinSize = 25;
	}
	// std::cout<<IoStream::lock;
	// std::cout<<"P"<<myIdx<<" input"<<std::endl;
	// for(u64 i = 0; i<inputSet_u8.size(); i++){
	// 	print_u8vec(inputSet_u8[i]);
	// }
	// //print_block(inputSet_block);
	// std::cout<<IoStream::unlock;

	Timer timer;
	timer.reset();
	int gc_sent = 0;
	int gc_recv = 0;
	auto start = timer.setTimePoint("start");

	// protocol
	// 1.key exchange
	// Curve
	REllipticCurve curve; //(CURVE_25519)
	PRNG prng(_mm_set_epi32(19249, 4923, 234435, 1231));
	PRNG prng_r(_mm_set_epi32(4253465, 3434565, 234435, 1231));
	// generater g
	const auto &g = curve.getGenerator();
	// sk
	std::vector<u8> sk_vec(g.sizeBytes() - 1); // 32 Bytes
	// g^sk
	std::vector<u8> gsk_vec(g.sizeBytes()); // 33 Bytes, y at index[][0]
	// pk
	std::vector<u8> pk_vec(g.sizeBytes());

	if (myIdx == 1)
	{
		REccNumber sk(curve);

		sk.randomize(prng);

		sk.toBytes(sk_vec.data());

		REccPoint g_sk = g * sk;
		g_sk.toBytes(gsk_vec.data());

		REccPoint pk = g_sk;

		pk.toBytes(pk_vec.data());

		// multi thread
		std::vector<std::thread> pThrds(nParties - 1);
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]()
									   {
				if(pIdx == 0){
					chls[1][0].send(pk_vec.data(), pk_vec.size());
				}else{
					chls[1][pIdx+1].send(pk_vec.data(), pk_vec.size());
				} });
		}
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();
	}
	else
	{
		chls[myIdx][1].recv(pk_vec.data(), pk_vec.size());
	}

	PRNG prng_enc(_mm_set_epi32(4253465, 3434565, 234435, 1231));

	// All the parties compute the X' = Enc(pk,X)
	// encrypt_set: setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_set;

	for (u64 i = 0; i < inputSet_u8.size(); i++)
	{
		// std::cout<<inputSet_u8[i]<<std::endl;
		// print_u8vec(pk_vec);
		std::vector<std::vector<u8>> ciphertext = encryption(inputSet_u8[i], pk_vec, prng_enc);
		encrypt_set.push_back(ciphertext);
	}

	// p0 init V
	std::vector<std::vector<std::vector<u8>>> set_V;
	if (myIdx == 0)
	{
		set_V = encrypt_set;
	}
	// set U
	std::vector<std::vector<u8>> set_U;

	////All the parties compute the Enc(pk,0)
	// setSize * 2 * 33 u8 vector
	std::vector<std::vector<std::vector<u8>>> encrypt_zero_set;
	for (u64 i = 0; i < 1.27 * setSize; i++)
	{
		// std::cout<<inputSet_u8[i]<<std::endl;
		// print_u8vec(pk_vec);
		std::vector<u8> zero_u8(32, 0);
		std::vector<std::vector<u8>> ciphertext = encryption(zero_u8, pk_vec, prng_enc);
		encrypt_zero_set.push_back(ciphertext);
	}

	//=============================   End of Local Execution   ================================

	auto online = timer.setTimePoint("online_start");

	//=============================   OPRF Execution ==========================================
	if (myIdx == 0)
	{
		// 2.=============================== OPRF P_0 & P_i ==================================
		// update channel for oprf
		std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
		chlsoprf[0][1] = chls[0][1];

		std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

		oprf_value = aes_oprf(0, inputSet_block, 2 * setSize, chlsoprf, ZeroBlock);
		inputSet_block = oprf_value;
	}
	else if (myIdx == 1)
	{
		std::vector<osuCrypto::block> oprf_value;
		// AES_KEY for OPRF
		PRNG prngOPRF(_mm_set_epi32(123, 3434565, 234435, 23987054));
		std::vector<osuCrypto::block> oprf_key = {prngOPRF.get<osuCrypto::block>()};

		// multi thread
		std::vector<std::thread> pThrds(nParties - 1);
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		{
			pThrds[pIdx] = std::thread([&, pIdx]()
									   {
				if(pIdx == 0){
					//----------------- with P1 -----------------
					// update channel for oprf
					std::vector<std::vector<Channel>> chlsoprf(2, std::vector<Channel>(2));
					chlsoprf[1][0] = chls[1][0];
					oprf_value = aes_oprf(1, inputSet_block, 2 * setSize, chlsoprf, oprf_key[0]);
					inputSet_block = oprf_value;
				}else{
					//------------------ with others ----------------
					// 4.OPRF key sharing
					chls[1][pIdx+1].send(oprf_key.data(), oprf_key.size());
				} });
		}
		for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
			pThrds[pIdx].join();
	}
	else
	{
		// 4.OPRF key sharing
		//
		std::vector<osuCrypto::block> recv_oprf_key(1);
		chls[myIdx][1].recv(recv_oprf_key.data(), recv_oprf_key.size());

		AES aes_oprf(recv_oprf_key[0]);

		std::vector<osuCrypto::block> oprf_value(inputSet_block.size());

		aes_oprf.ecbEncBlocks(inputSet_block.data(), inputSet_block.size(), oprf_value.data());

		inputSet_block = oprf_value;
	}

	// auto oprf = timer.setTimePoint("oprf_end");
	// cuckoo and simple hashing

	u64 tablesize = 1.27 * setSize;
	SimpleTable simple;
	CuckooTable cuckoo;

	if (myIdx == 0)
	{
		//----------------simple hashing--------------------

		PRNG simple_dummy(_mm_set_epi32(4253465, 3434565, 234435, 1234567 + myIdx));

		simple.init(1.27, setSize, 3);

		for (u64 i = 0; i < setSize; i++)
		{
			simple.insertItems(inputSet_block[2 * i]);
		}

		// std::cout << "max bin size: " << simple.getMaxBinSize() << std::endl;
		//  std::cout<<IoStream::lock;
		//  simple.print_table();
		//  std::cout<<IoStream::unlock;
		simple.padGlobalItems(simple_dummy, maxBinSize);

		//--------------------------------------------------
	}
	else
	{
		//----------------cuckoo hashing--------------------
		PRNG cuckoo_dummy(_mm_set_epi32(4253465, 3434565, 23232435, 1234567 + myIdx));

		cuckoo.init(1.27, setSize, 3);
		for (u64 i = 0; i < setSize; i++)
		{
			cuckoo.insertItem(inputSet_block[2 * i], i);
		}

		// std::cout<<IoStream::lock;
		// cuckoo.print_table();
		// std::cout<<IoStream::unlock;

		cuckoo.padGlobalItems(cuckoo_dummy);

		//--------------------------------------------------
	}
	auto hash = timer.setTimePoint("hash & porf_end");
	//===============================   mOT Execution   ================================

	for (u64 round = 1; round < nParties; round++)
	{
		// P_0
		if (myIdx == 0)
		{
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[0][1] = chls[0][round];

			// rpir_batched
			std::vector<osuCrypto::block> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO("127.0.0.1", 6000 + round);

				setup_semi_honest(io, 2);

				aes_keys = rpir_batched_receiver(chlsrpir, simple.items, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = rpir_batched_receiver_ngc(chlsrpir, simple.items);
			}
			// // rpir_batched

			// emp::NetIO *io = new NetIO("127.0.0.1", 6000 + round);
			// setup_semi_honest(io, 2);

			// std::vector<osuCrypto::block> aes_keys = rpir_batched_receiver(chlsrpir, simple.items, io, &gc_sent, &gc_recv);

			// 3.3 message parse & decrypt

			std::vector<osuCrypto::block> recv_rpir_message_all(14*simple.items.size());
			chls[0][round].recv(recv_rpir_message_all.data(),recv_rpir_message_all.size());

			for (u64 i = 0; i < simple.items.size(); i++)
			{
				// std::vector<osuCrypto::block> recv_aes_message(14);

				// chls[0][round].recv(recv_aes_message.data(), recv_aes_message.size());

				std::vector<osuCrypto::block> recv_aes_message = {recv_rpir_message_all.begin() + i * 14, recv_rpir_message_all.begin() + i * 14 + 14};

				// decrypt
				// message decode
				AESDec decryptor(aes_keys[i]);
				osuCrypto::block indicator = decryptor.ecbDecBlock(recv_aes_message[2]);
				std::vector<osuCrypto::block> rpir_message;
				if (indicator == toBlock(u64(0)) || indicator == toBlock(u64(1)) || indicator == toBlock(u64(2)) || indicator == toBlock(u64(3)))
				{
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[0]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[1]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[2]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[3]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[4]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[5]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[6]));
				}
				else
				{
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[7]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[8]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[9]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[10]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[11]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[12]));
					rpir_message.push_back(decryptor.ecbDecBlock(recv_aes_message[13]));
				}

				// received message of length 7
				// update X and V
				//[0:1]prf value

				simple.items[i].push_back(rpir_message[0]);
				//[2:6]ciphertext of element
				std::vector<osuCrypto::block> new_ctx_block = {rpir_message.begin() + 2, rpir_message.end()};
				std::vector<std::vector<u8>> new_ctx = blocks_to_ciphertexts(new_ctx_block);
				// update set_V
				set_V.push_back(new_ctx);
			}
			auto mot = timer.setTimePoint("mot_end");
		}
		else if (myIdx == round)
		{
			std::vector<std::vector<Channel>> chlsrpir(2, std::vector<Channel>(2));
			chlsrpir[1][0] = chls[round][0];
			//  rpir
			// emp::NetIO *io = new NetIO(nullptr, 6000 + round);
			// setup_semi_honest(io, 1);
			// std::vector<std::array<osuCrypto::block, 2>> aes_keys = rpir_batched_sender(chlsrpir, cuckoo.items, maxBinSize + round - 1, io, &gc_sent, &gc_recv);
			std::vector<std::array<osuCrypto::block, 2>> aes_keys;
			if (gc_used)
			{
				emp::NetIO *io = new NetIO(nullptr, 6000 + round);
				setup_semi_honest(io, 1);
				aes_keys = rpir_batched_sender(chlsrpir, cuckoo.items, maxBinSize + round - 1, io, &gc_sent, &gc_recv);
			}
			else
			{
				aes_keys = rpir_batched_sender_ngc(chlsrpir, cuckoo.items, maxBinSize + round - 1);
			}
			//  message construction & encryption

			PRNG prng_ot_aes(toBlock(12345678 + myIdx));
			
			std::vector<osuCrypto::block> ot_messages_all;

			for (u64 i = 0; i < cuckoo.items.size(); i++)
			{
				std::vector<osuCrypto::block> ot_messages;
				// for dummy value
				if (cuckoo.item_idx[i] == -1)
				{
					// v0
					// AES
					AES aes_0(aes_keys[i][0]);
					std::vector<osuCrypto::block> v0;
					//$
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero0 = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v0.insert(v0.end(), enc_zero0.begin(), enc_zero0.end());
					std::vector<osuCrypto::block> enc_v0(v0.size());
					aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
					ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());
					// v1
					// AES
					AES aes_1(aes_keys[i][1]);
					std::vector<osuCrypto::block> v1;
					//$
					v1.push_back(prng_ot_aes.get<osuCrypto::block>());
					v1.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero1 = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v1.insert(v1.end(), enc_zero1.begin(), enc_zero1.end());
					std::vector<osuCrypto::block> enc_v1(v1.size());
					aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
					ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());
				}
				// for real value
				else
				{
					// v0
					// AES
					AES aes_0(aes_keys[i][0]);
					std::vector<osuCrypto::block> v0;
					//$
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					v0.push_back(prng_ot_aes.get<osuCrypto::block>());
					// enc(0)
					std::vector<osuCrypto::block> enc_zero = ciphertexts_to_blocks(encrypt_zero_set[i]);
					v0.insert(v0.end(), enc_zero.begin(), enc_zero.end());
					std::vector<osuCrypto::block> enc_v0(v0.size());
					aes_0.ecbEncBlocks(v0.data(), v0.size(), enc_v0.data());
					ot_messages.insert(ot_messages.end(), enc_v0.begin(), enc_v0.end());

					// v1
					AES aes_1(aes_keys[i][1]);
					std::vector<osuCrypto::block> v1;
					// F(k,x)
					v1.push_back(inputSet_block[2 * cuckoo.item_idx[i]]);
					v1.push_back(inputSet_block[2 * cuckoo.item_idx[i] + 1]);
					// Enc(x)
					std::vector<osuCrypto::block> enc_x = ciphertexts_to_blocks(encrypt_set[cuckoo.item_idx[i]]);
					v1.insert(v1.end(), enc_x.begin(), enc_x.end());
					std::vector<osuCrypto::block> enc_v1(v1.size());
					aes_1.ecbEncBlocks(v1.data(), v1.size(), enc_v1.data());
					ot_messages.insert(ot_messages.end(), enc_v1.begin(), enc_v1.end());

					// if(i == 0 && round == 1){
					// 	print_block(rpir_input);
					// 	std::cout<<"size of rpir input: "<<rpir_input.size()<<std::endl;
					// }
				}

				ot_messages_all.insert(ot_messages_all.end(),ot_messages.begin(),ot_messages.end());
				// chls[round][0].send(ot_messages.data(), ot_messages.size());
			}
			chls[round][0].send(ot_messages_all.data(), ot_messages_all.size());
			auto mot = timer.setTimePoint("mot_end");

			// std::cout<<ot_messages.size()<<std::endl;
		}
	}

	// 5.Decrypt & shuffle
	if (myIdx == 0)
	{
		// shuffle not included for now
		// we can shuffle set_V;
		shuffle(set_V.begin(), set_V.end(), prng);

		std::vector<osuCrypto::block> set_V_block;

		for (u64 i = 0; i < set_V.size(); i++)
		{
			std::vector<osuCrypto::block> ctx_block = ciphertexts_to_blocks(set_V[i]);
			set_V_block.insert(set_V_block.end(), ctx_block.begin(), ctx_block.end());
		}
		chls[0][1].send(set_V_block.data(), set_V_block.size());
	}
	else if (myIdx == 1)
	{
		auto decrypt_start1 = timer.setTimePoint("decrypt_start1");
		std::vector<osuCrypto::block> recv_set_V_block(((nParties - 1) * tablesize + setSize) * 5);
		chls[1][0].recv(recv_set_V_block.data(), recv_set_V_block.size());
		auto decrypt_start2 = timer.setTimePoint("decrypt_start2");
		for (u64 i = 0; i < recv_set_V_block.size() / 5; i++)
		{
			std::vector<osuCrypto::block> ctx_block1 = {recv_set_V_block.begin() + 5 * i, recv_set_V_block.begin() + 5 * i + 5};
			std::vector<std::vector<u8>> ctx_u8 = blocks_to_ciphertexts(ctx_block1);
			std::vector<u8> element = decryption(ctx_u8, sk_vec);
			// print_u8vec(element);
			std::vector<u8> zero(32);
			if (element != zero)
				set_U.push_back(element);
		}
	}

	auto end = timer.setTimePoint("decrypt_end");

	std::cout << IoStream::lock;
	std::cout << " party " << myIdx << "\t" << timer << std::endl;

	double dataSent = 0, dataRecv = 0; //, Mbps = 0, MbpsRecv = 0;

	for (u64 j = 0; j < nParties; ++j)
	{
		if (j != myIdx)
		{
			dataSent += chls[myIdx][j].getTotalDataSent();
			dataRecv += chls[myIdx][j].getTotalDataRecv();
		}
	}

	std::cout << "party #" << myIdx << "\t Comm Send: " << ((dataSent) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t Comm Recv: " << ((dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t GC Comm Send: " << (gc_sent / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << "party #" << myIdx << "\t GC Recv Recv: " << (gc_recv / std::pow(2.0, 20)) << " MB" << std::endl;
	// std::cout << "party #" << myIdx << "\t Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	std::cout << IoStream::unlock;
}

inline void mpsu_test()
{
	const u64 numThreads_max = std::thread::hardware_concurrency();
	std::cout<<"max number of threads: "<< numThreads_max<<std::endl;
	// std::vector<u64> set_sizes = {1 << 8, 1 << 12, 1 << 16};
	std::vector<u64> set_sizes = {1 << 16};
	// std::vector<u64> num_parties = {3, 4, 6, 8};
	std::vector<u64> num_parties = {4};

	for (auto setSize : set_sizes)
	{
		for (auto nParties : num_parties)
		{
			for (int iteration = 0; iteration < 1; iteration++)
			{

				// u64 setSize = 1 << 8;
				// u64 psiSecParam = 40;
				// u64 bitSize = 128;
				// u64 nParties = 3;

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
											    //   psu1(inputSet_u8[pIdx], inputSet_block[pIdx], nParties, pIdx, setSize, chls);
											    psu2_multiThread(inputSet_u8[pIdx], inputSet_block[pIdx], nParties, pIdx, setSize, chls); 
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
