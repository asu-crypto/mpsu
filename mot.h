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
// #include "simpletable.h"
// #include "cuckootable.h"
#include "gc.h"

using namespace osuCrypto;

inline std::vector<osuCrypto::block> mot_batched_receiver_ngc_multiThreads(std::vector<std::vector<Channel>> chls, std::vector<std::vector<osuCrypto::block>> inputSet,int numThreads)
{	
	AES hashOKVS(toBlock(12138));
	PRNG secret_value_generater(_mm_set_epi32(4253465, 12365, 234435, 23987054));
	BitVector choices(inputSet.size());
	u64 okvs_size = inputSet[0].size() * okvsLengthScale;
	std::vector<osuCrypto::block> secret_values(inputSet.size());
	std::vector<osuCrypto::block> okvs_table_batched(inputSet.size()*okvs_size);
	std::vector<u64> numbers_to_compare(inputSet.size());

	//receiver
	vector<thread> threads(numThreads);
	u64 batch_size1 = inputSet.size()/numThreads;

   	for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
			u64 start,end;
			start = t*batch_size1;
			if(t!=numThreads-1){
				end = (t+1)*batch_size1;
			}else{
				end = inputSet.size();
			}
			for(u64 i = start; i < end; i++){
				secret_values[i] = secret_value_generater.get<osuCrypto::block>();
			}

			for (u64 i = start; i < end; i++)
			{	
				// 1.okvs
				osuCrypto::block secret_value = secret_values[i];
				// std::cout<<"secret value: "<<secret_value<<std::endl;
				std::vector<osuCrypto::block> input = inputSet[i];
				std::vector<osuCrypto::block> okvs_value(input.size());
				hashOKVS.ecbEncBlocks(input.data(), input.size(), okvs_value.data());
				for (u64 j = 0; j < okvs_value.size(); j++)
				{
					okvs_value[j] = okvs_value[j] ^ secret_value;
				}
				// std::cout<<"okvs value: "<<okvs_value[0]<<std::endl;
				std::vector<osuCrypto::block> okvs_table(okvs_size);
				GbfEncode(input, okvs_value, okvs_table);
				// okvs_table_batched.insert(okvs_table_batched.end(),okvs_table.begin(),okvs_table.end());
				std::copy(okvs_table.begin(),okvs_table.end(),okvs_table_batched.begin()+i*okvs_size);
				// std::copy(inter_vec.begin(),inter_vec.end(),inter_data.begin()+(i)*33);
				// chls[0][1].send(okvs_table.data(), okvs_table.size());
				// std::cout<<"recver "<<i<<std::endl;
			}

			for(u64 i = start; i < end; i++)
			{	
				// std::cout<<i<<std::endl;
				// 2.gc
				u8 result = 0;
				u64 number_to_compare;
				osuCrypto::block secret_value = secret_values[i];
				memcpy(&number_to_compare, &secret_value, sizeof(number_to_compare));
				numbers_to_compare[i] = number_to_compare;
				// std::cout << "num:"<<number_to_compare<<std::endl;
				// bool bR = _AeqB(io, 1, number_to_compare);
				// // bool bS = z[0].reveal<bool>();
				// // bool bR = z[1];//.reveal<bool>();

				// result = bR;
				// // 3.1 circuit_psi
				// choices[i] = result;
				choices[i] = 1;
			}

	   });
   	}
	
   	for(int t = 0;t<numThreads;t++){
       threads[t].join();
   	}
	
	chls[0][1].send(okvs_table_batched.data(), okvs_table_batched.size());


	// *comm_recv += io->total_recv;
	// *comm_sent += io->total_sent;
	// delete io;
	
	// 3.2 ot extension
	PRNG prng(sysRandomSeed());
	IknpOtExtReceiver recver;
	std::vector<osuCrypto::block> recv_u_blocks(inputSet.size());
	chls[0][1].recv(recv_u_blocks.data(), recv_u_blocks.size());
	// Receive the messages
	std::vector<osuCrypto::block> messages(inputSet.size());
	recver.receiveChosen(choices, messages, prng, chls[0][1]);
	std::vector<osuCrypto::block> aes_keys(inputSet.size());

	for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
			u64 start,end;
			start = t*batch_size1;
			if(t!=numThreads-1){
				end = (t+1)*batch_size1;
			}else{
				end = inputSet.size();
			}

			for (u64 i = start; i < end; i++)
			{
				aes_keys[i] = recv_u_blocks[i] ^ messages[i];
			}

	 });
   	}
	
   	for(int t = 0;t<numThreads;t++){
       threads[t].join();
   	}

	return aes_keys;
}

inline std::vector<std::array<osuCrypto::block, 2>> mot_batched_sender_ngc_multiThreads(std::vector<std::vector<Channel>> chls, std::vector<osuCrypto::block> inputSet, u64 maxBinSize,int numThreads)
{	
	// sender
	AES hashOKVS(toBlock(12138));
	// BitVector b_s_vec(inputSet.size());
	u64 okvs_size = maxBinSize * okvsLengthScale;
	std::vector<osuCrypto::block> received_values(inputSet.size());
	std::vector<osuCrypto::block> recv_okvs_table_batched (inputSet.size()*okvs_size);
	vector<u64> numbers_to_compare(inputSet.size());
	std::vector<u8> b_s_vec (numbers_to_compare.size());
	PRNG prng(sysRandomSeed());
	IknpOtExtSender sender;
	std::vector<std::array<osuCrypto::block, 2>> sendMessages(inputSet.size());
	// Choose which messages should be sent.
	std::vector<std::array<osuCrypto::block, 2>> aes_keys(inputSet.size());
	std::vector<osuCrypto::block> u_blocks(inputSet.size());
	PRNG prng_ot_aes(_mm_set_epi32(4253465, 1265, 234435, 23987054));

	
	chls[1][0].recv(recv_okvs_table_batched.data(), recv_okvs_table_batched.size());

	vector<thread> threads(numThreads);
	u64 batch_size1 = inputSet.size()/numThreads;

   	for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
			u64 start,end;
			start = t*batch_size1;
			if(t!=numThreads-1){
				end = (t+1)*batch_size1;
			}else{
				end = inputSet.size();
			}

			for (u64 i = start; i < end; i++)
			{	
				// 1.okvs
				std::vector<osuCrypto::block> recv_okvs_table = {recv_okvs_table_batched.begin()+i*okvs_size,recv_okvs_table_batched.begin()+(i+1)*okvs_size};
				// chls[1][0].recv(recv_okvs_table.data(), recv_okvs_table.size());
				
				// first half of y, enough for equality check
				std::vector<osuCrypto::block> y;
				y.push_back(inputSet[i]);
				std::vector<osuCrypto::block> decoded_value(1);
				GbfDecode(recv_okvs_table, y, decoded_value);
				std::vector<osuCrypto::block> H_y(1);
				hashOKVS.ecbEncBlocks(y.data(), y.size(), H_y.data());
				osuCrypto::block received_value = H_y[0] ^ decoded_value[0];
				// std::cout<<"sender "<<i<<std::endl;
				// received_values.push_back(received_value);
				received_values[i] = received_value;
			}

			for (u64 i = start; i < end; i++)
			{
				// std::cout<<"s: "<<i<<std::endl;
				// 2.gc
				//===========sim=============
				u8 result = 0;
				u64 number_to_compare;
				osuCrypto::block received_value = received_values[i];
				memcpy(&number_to_compare, &received_value, sizeof(number_to_compare));
				numbers_to_compare[i] = number_to_compare;
				// bool bS = _AeqB(io, 2, number_to_compare);
				// // bool bS = z[0];//.reveal<bool>();
				// // bool bR = z[1].reveal<bool>();
				// result = !bS;
				// //===========sim=============
				b_s_vec[i] = 1;
			}

			// *comm_recv += io->total_recv;
			// *comm_sent += io->total_sent;
			// delete io;
			// 3.2 ot sender
			

			for (u64 i = start; i < end; i++)
			{
				aes_keys[i] = {prng_ot_aes.get<osuCrypto::block>(), prng_ot_aes.get<osuCrypto::block>()};
				osuCrypto::block r = prng.get<osuCrypto::block>();
				osuCrypto::block u;
				if (b_s_vec[i] == 1)
				{
					u = r ^ aes_keys[i][0] ^ aes_keys[i][1];
				}
				else
				{
					u = r;
				}
				u_blocks[i] = u;
				sendMessages[i][0] = r ^ aes_keys[i][0];
				sendMessages[i][1] = r ^ aes_keys[i][1];
			}

		});
   	}
	
   	for(int t = 0;t<numThreads;t++){
       threads[t].join();
   	}

	
	chls[1][0].send(u_blocks.data(), u_blocks.size());
	// Send the messages.
	sender.sendChosen(sendMessages, prng, chls[1][0]);
	return aes_keys;
}

inline std::vector<osuCrypto::block> mot_batched_receiver(std::vector<std::vector<Channel>> chls, std::vector<std::vector<osuCrypto::block>> inputSet, emp::NetIO *io,int *comm_sent, int *comm_recv)
{	
	AES hashOKVS(toBlock(12138));
	PRNG secret_value_generater(_mm_set_epi32(4253465, 12365, 234435, 23987054));
	BitVector choices(inputSet.size());
	u64 okvs_size = inputSet[0].size() * okvsLengthScale;
	std::vector<osuCrypto::block> secret_values;
	std::vector<osuCrypto::block> okvs_table_batched;
	std::vector<u64> numbers_to_compare(inputSet.size());

	for(u64 i = 0; i < inputSet.size(); i++){
		secret_values.push_back(secret_value_generater.get<osuCrypto::block>());
	}

	
	for (u64 i = 0; i < inputSet.size(); i++)
	{	
		// 1.okvs
		osuCrypto::block secret_value = secret_values[i];

		std::vector<osuCrypto::block> input = inputSet[i];
		std::vector<osuCrypto::block> okvs_value(input.size());
		hashOKVS.ecbEncBlocks(input.data(), input.size(), okvs_value.data());
		for (u64 j = 0; j < okvs_value.size(); j++)
		{
			okvs_value[j] = okvs_value[j] ^ secret_value;
		}

		std::vector<osuCrypto::block> okvs_table(okvs_size);
		GbfEncode(input, okvs_value, okvs_table);
		okvs_table_batched.insert(okvs_table_batched.end(),okvs_table.begin(),okvs_table.end());
		// chls[0][1].send(okvs_table.data(), okvs_table.size());
		// std::cout<<"recver "<<i<<std::endl;
	}
	
	chls[0][1].send(okvs_table_batched.data(), okvs_table_batched.size());
	for(u64 i = 0; i < inputSet.size(); i++)
	{	

		// 2.gc
		u8 result = 0;
		u64 number_to_compare;
		osuCrypto::block secret_value = secret_values[i];
		memcpy(&number_to_compare, &secret_value, sizeof(number_to_compare));
		numbers_to_compare[i] = number_to_compare;

	}
	auto bRs = _AeqB(io, 1, numbers_to_compare);

	for(u64 i =0;i<choices.size();i++){
		choices[i] = bRs[i];
		// choices[i] = 1;
	}
	
	*comm_recv += io->total_recv;
	*comm_sent += io->total_sent;
	delete io;
	
	// 3.2 ot extension
	PRNG prng(sysRandomSeed());
	IknpOtExtReceiver recver;
	std::vector<osuCrypto::block> recv_u_blocks(inputSet.size());
	chls[0][1].recv(recv_u_blocks.data(), recv_u_blocks.size());
	// Receive the messages
	std::vector<osuCrypto::block> messages(inputSet.size());
	recver.receiveChosen(choices, messages, prng, chls[0][1]);
	std::vector<osuCrypto::block> aes_keys(inputSet.size());
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		aes_keys[i] = recv_u_blocks[i] ^ messages[i];
	}
	return aes_keys;
}

inline std::vector<std::array<osuCrypto::block, 2>> mot_batched_sender(std::vector<std::vector<Channel>> chls, std::vector<osuCrypto::block> inputSet, u64 maxBinSize, emp::NetIO *io,int *comm_sent, int *comm_recv)
{	
	// sender
	AES hashOKVS(toBlock(12138));
	// BitVector b_s_vec(inputSet.size());
	u64 okvs_size = maxBinSize * okvsLengthScale;
	std::vector<osuCrypto::block> received_values;
	std::vector<osuCrypto::block> recv_okvs_table_batched (inputSet.size()*okvs_size);
	vector<u64> numbers_to_compare(inputSet.size());
	
	chls[1][0].recv(recv_okvs_table_batched.data(), recv_okvs_table_batched.size());
	for (u64 i = 0; i < inputSet.size(); i++)
	{	
		// 1.okvs
		std::vector<osuCrypto::block> recv_okvs_table = {recv_okvs_table_batched.begin()+i*okvs_size,recv_okvs_table_batched.begin()+(i+1)*okvs_size};
		// chls[1][0].recv(recv_okvs_table.data(), recv_okvs_table.size());
		
		// first half of y, enough for equality check
		std::vector<osuCrypto::block> y;
		y.push_back(inputSet[i]);
		std::vector<osuCrypto::block> decoded_value(1);
		GbfDecode(recv_okvs_table, y, decoded_value);
		std::vector<osuCrypto::block> H_y(1);
		hashOKVS.ecbEncBlocks(y.data(), y.size(), H_y.data());
		osuCrypto::block received_value = H_y[0] ^ decoded_value[0];
		// std::cout<<"sender "<<i<<std::endl;
		received_values.push_back(received_value);
	}
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		// 2.gc
		//===========sim=============
		u8 result = 0;
		u64 number_to_compare;
		osuCrypto::block received_value = received_values[i];
		memcpy(&number_to_compare, &received_value, sizeof(number_to_compare));
		numbers_to_compare[i] = number_to_compare;

	}
	
	auto b_s_vec = _AeqB(io, 2, numbers_to_compare);


	*comm_recv += io->total_recv;
	*comm_sent += io->total_sent;
	delete io;
	// 3.2 ot sender
	PRNG prng(sysRandomSeed());
	IknpOtExtSender sender;
	std::vector<std::array<osuCrypto::block, 2>> sendMessages(inputSet.size());
	// Choose which messages should be sent.
	std::vector<std::array<osuCrypto::block, 2>> aes_keys(inputSet.size());
	std::vector<osuCrypto::block> u_blocks;
	PRNG prng_ot_aes(_mm_set_epi32(4253465, 1265, 234435, 23987054));
	for (u64 i = 0; i < inputSet.size(); i++)
	{
		aes_keys[i] = {prng_ot_aes.get<osuCrypto::block>(), prng_ot_aes.get<osuCrypto::block>()};
		osuCrypto::block r = prng.get<osuCrypto::block>();
		osuCrypto::block u;
		if (b_s_vec[i] == 1)
		{
			u = r ^ aes_keys[i][0] ^ aes_keys[i][1];
		}
		else
		{
			u = r;
		}
		u_blocks.push_back(u);
		sendMessages[i][0] = r ^ aes_keys[i][0];
		sendMessages[i][1] = r ^ aes_keys[i][1];
	}
	chls[1][0].send(u_blocks.data(), u_blocks.size());
	// Send the messages.
	sender.sendChosen(sendMessages, prng, chls[1][0]);
	return aes_keys;
}
