#pragma once
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/AES.h>
#include "gbf.h"
#include "utl.h"
#include "eccConvert.h"

using namespace osuCrypto;
inline std::vector<osuCrypto::block> dh_prf(std::vector<osuCrypto::block> x, std::vector<osuCrypto::block> key)
{
	REllipticCurve curve; //(CURVE_25519)
	// generater g
	const auto &g = curve.getGenerator();
	// x is 1 block (element in cuckoo hash table)
	AES pubHash(toBlock(12138));
	std::vector<osuCrypto::block> H_q(x.size());

	pubHash.ecbEncBlocks(x.data(), x.size(), H_q.data());

	std::vector<u8> hq_vec = block_to_u8vec(H_q[0], 32);

	REccNumber hq_num(curve);
	hq_num.fromBytes(hq_vec.data());
	//comment out for comparision
	REccPoint x_point = g * hq_num;

	std::vector<u8> key_vec = blocks_to_u8vec(key);

	REccNumber key_num(curve);
	key_num.fromBytes(key_vec.data());
	//comment out for comparision
	x_point *= key_num;

	std::vector<u8> result_vec(33);
	x_point.toBytes(result_vec.data());

	result_vec.erase(result_vec.begin());

	std::vector<osuCrypto::block> result = u8vec_to_blocks(result_vec);
	return result;
}
inline std::vector<osuCrypto::block> dh_oprf(AES pubHash, REllipticCurve curve, u64 myIdx, std::vector<osuCrypto::block> x, std::vector<std::vector<Channel>> chls)
{
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 1041));
	// REllipticCurve curve; //(CURVE_25519)

	// generater g
	// auto &g = curve.getGenerator();

	// receiver
	if (myIdx == 0)
	{

		// x is 1 block (element in cuckoo hash table)
		// AES pubHash(toBlock(12138));

		std::vector<osuCrypto::block> H_q(x.size());

		pubHash.ecbEncBlocks(x.data(), x.size(), H_q.data());

		std::vector<u8> hq_vec = block_to_u8vec(H_q[0], 32);

		REccNumber hq_num(curve);

		hq_num.fromBytes(hq_vec.data());


		// hq_num.randomize(prng);

		REccPoint x_point = curve.getGenerator() * hq_num;

		REccNumber a(curve);
		a.randomize(prng);

		// x_point *= a;

		// a.inverse();

		std::vector<u8> x(33);
		x_point.toBytes(x.data());

		chls[0][1].send(x.data(), x.size());

		chls[0][1].recv(x.data(), x.size());

		x_point.fromBytes(x.data());

		// inverse always outputs 1
		//  a = a.inverse();
		//  std::vector<u8> a_vec(32);
		//  a.toBytes(a_vec.data());
		//  print_u8vec(a_vec);

		// x_point *= a.inverse();

		x_point.toBytes(x.data());
		x.erase(x.begin());
		std::vector<osuCrypto::block> result = u8vec_to_blocks(x);
		return result;
	}
	// sender

	else if (myIdx == 1)
	{

		// input is key of 2 block
		std::vector<u8> recv_x_vec(33);

		chls[1][0].recv(recv_x_vec.data(), recv_x_vec.size());

		REccPoint x_point;
		x_point.fromBytes(recv_x_vec.data());

		// print_block(x);
		std::vector<u8> b_vec = blocks_to_u8vec(x);

		REccNumber b(curve);

		b.fromBytes(b_vec.data());

		x_point *= b;

		x_point.toBytes(recv_x_vec.data());

		chls[1][0].send(recv_x_vec.data(), recv_x_vec.size());
		// return the key
		return x;
	}
}

inline std::vector<osuCrypto::block> dh_oprf_async(AES pubHash, REllipticCurve curve, u64 myIdx, std::vector<osuCrypto::block> x, std::vector<std::vector<Channel>> chls)
{
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 1041));
	// REllipticCurve curve; //(CURVE_25519)

	// generater g
	// auto &g = curve.getGenerator();

	std::vector<u8> zero(33, 0);
	// receiver
	if (myIdx == 0)
	{

		// x is 1 block (element in cuckoo hash table)
		// AES pubHash(toBlock(12138));

		std::vector<osuCrypto::block> H_q(x.size());

		pubHash.ecbEncBlocks(x.data(), x.size(), H_q.data());

		std::vector<u8> hq_vec = block_to_u8vec(H_q[0], 32);

		REccNumber hq_num(curve);

		hq_num.fromBytes(hq_vec.data());
		// hq_num.randomize(prng);

		REccPoint x_point = curve.getGenerator() * hq_num;

		REccNumber a(curve);
		a.randomize(prng);

		// x_point *= a;

		// a.inverse();

		std::vector<u8> x(33);
		x_point.toBytes(x.data());

		chls[0][1].asyncSend(x.data(), x.size());
		std::cout << "1" << std::endl;
		chls[0][1].asyncRecv(x.data(), x.size());
		if (x != zero)
		{
			x_point.fromBytes(x.data());

			// inverse always outputs 1
			//  a = a.inverse();
			//  std::vector<u8> a_vec(32);
			//  a.toBytes(a_vec.data());
			//  print_u8vec(a_vec);

			// x_point *= a.inverse();

			x_point.toBytes(x.data());
			x.erase(x.begin());
			std::vector<osuCrypto::block> result = u8vec_to_blocks(x);
			return result;
		}
	}
	// sender

	else if (myIdx == 1)
	{

		// input is key of 2 block
		std::vector<u8> recv_x_vec(33);

		chls[1][0].asyncRecv(recv_x_vec.data(), recv_x_vec.size());
		std::cout << "2" << std::endl;
		if (recv_x_vec != zero)
		{
			REccPoint x_point;
			x_point.fromBytes(recv_x_vec.data());

			// print_block(x);
			std::vector<u8> b_vec = blocks_to_u8vec(x);

			REccNumber b(curve);

			b.fromBytes(b_vec.data());

			x_point *= b;

			x_point.toBytes(recv_x_vec.data());
		}
		std::cout << "3" << std::endl;
		chls[1][0].asyncSend(recv_x_vec.data(), recv_x_vec.size());
		// return the key
		return x;
	}
}

inline std::vector<osuCrypto::block> aes_oprf(u64 myIdx, std::vector<osuCrypto::block> input, u64 setSize, std::vector<std::vector<Channel>> chls, osuCrypto::block AES_key)
{
	// receiver
	if (myIdx == 0)
	{

		std::vector<osuCrypto::block> recv_okvs_table(setSize * okvsLengthScale);

		chls[0][1].recv(recv_okvs_table.data(), recv_okvs_table.size());

		std::vector<osuCrypto::block> oprf_value(input.size());
		GbfDecode(recv_okvs_table, input, oprf_value);
		// print_block(oprf_value);
		return oprf_value;
	}
	// sender
	else if (myIdx == 1)
	{

		AES aes_oprf(AES_key);

		std::vector<osuCrypto::block> oprf_value(input.size());

		aes_oprf.ecbEncBlocks(input.data(), input.size(), oprf_value.data());
		// print_block(oprf_value);

		std::vector<osuCrypto::block> okvs_table(input.size() * okvsLengthScale);

		GbfEncode(input, oprf_value, okvs_table);

		chls[1][0].send(okvs_table.data(), okvs_table.size());

		return oprf_value;
	}
	else
	{
		return std::vector<osuCrypto::block>{toBlock(u64(0))};
	}
}

inline void oprf_test()
{
	u64 setSize = 1 << 1;
	// u64 psiSecParam = 40;
	// u64 bitSize = 128;
	u64 nParties = 2;

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
	REllipticCurve curve; //(CURVE_25519)
	AES pubHash(toBlock(12138));
	REccPoint g = curve.getGenerator();
	for (u64 i = 0; i < nParties; i++)
	{
		PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
		PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
		// std::cout<<"input from party "<<i<<std::endl;

		// generater g

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

	PRNG prngAES(_mm_set_epi32(123, 3434565, 234435, 23987054));
	std::vector<osuCrypto::block> AES_keys;
	AES_keys.push_back(prngAES.get<osuCrypto::block>());
	std::cout << inputSet_block.size() << std::endl;
	std::cout << inputSet_block[0].size() << std::endl;
	std::vector<osuCrypto::block> keys = {inputSet_block[1][0], inputSet_block[1][1]};
	std::vector<osuCrypto::block> a = {inputSet_block[0][0]};
	// thread
	std::vector<std::thread> pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]()

								   {
									   // block a = toBlock(123);
									   // block result = dh_oprf(pIdx,a,chls);
									   // std::cout<<"result "<<pIdx<<" "<<result<<std::endl;

									   // std::vector<osuCrypto::block> result = aes_oprf(pIdx, inputSet[pIdx], setSize,chls,AES_keys[0]);
									
										if(pIdx == 0){

												//std::vector<osuCrypto::block> input = {toBlock(u64(123))};
												std::vector<osuCrypto::block> result = dh_oprf(pubHash,curve,pIdx, a, chls);
												//print_block(result);									

									   }
									   else if (pIdx == 1){

											std::vector<osuCrypto::block> result = dh_oprf(pubHash,curve,pIdx, keys, chls);
											//std::vector<osuCrypto::block> input = {toBlock(u64(123))};
										//std::vector<osuCrypto::block> result2 = dh_prf(input,inputSet_block[pIdx]);
										//print_block(result2);
										
									   } });
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
