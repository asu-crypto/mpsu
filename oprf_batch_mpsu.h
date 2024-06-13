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
#include "oprf_mpsu.h"

using namespace osuCrypto;

inline std::vector<osuCrypto::block> dh_oprf_batched(AES pubHash, REllipticCurve curve, u64 myIdx, std::vector<osuCrypto::block> x, std::vector<std::vector<Channel>> chls, u64 size_oprf)
{
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 1041));
    if (myIdx == 0)
    {
        std::vector<u8> inter_data;
        for (u64 i = 0; i < size_oprf; i++)
        {

            std::vector<osuCrypto::block> oprf_value = {x[i]};
            std::vector<osuCrypto::block> H_q(oprf_value.size());

            pubHash.ecbEncBlocks(oprf_value.data(), oprf_value.size(), H_q.data());

            std::vector<u8> hq_vec = block_to_u8vec(H_q[0], 32);

            REccNumber hq_num(curve);

            hq_num.fromBytes(hq_vec.data());

            // hq_num.randomize(prng);

            REccPoint x_point = curve.getGenerator() * hq_num;

            REccNumber a(curve);

            a.randomize(prng);

            // x_point *= a;
            // a.inverse();
            std::vector<u8> inter_vec(33);

            x_point.toBytes(inter_vec.data());

            inter_data.insert(inter_data.end(), inter_vec.begin(), inter_vec.end());
        }

        chls[0][1].send(inter_data.data(), inter_data.size());

        chls[0][1].recv(inter_data.data(), inter_data.size());

        std::vector<osuCrypto::block> result;

        for (u64 i = 0; i < size_oprf; i++)
        {
            std::vector<u8> inter_vec = {inter_data.begin() + 33 * i, inter_data.begin() + 33 * (i + 1)};
            REccPoint x_point(curve);
            x_point.fromBytes(inter_vec.data());
            // inverse always outputs 1
            //  a = a.inverse();
            //  std::vector<u8> a_vec(32);
            //  a.toBytes(a_vec.data());
            //  print_u8vec(a_vec);

            // x_point *= a.inverse();

            x_point.toBytes(inter_vec.data());
            inter_vec.erase(inter_vec.begin());
            std::vector<osuCrypto::block> inter_block = u8vec_to_blocks(inter_vec);
            // result.insert(result.end(), inter_block.begin(), inter_block.end());
            result.push_back(inter_block[0]);
        }
        return result;
    }
    else if (myIdx == 1)
    {
        std::vector<u8> rec_inter_data(33 * size_oprf);
        chls[1][0].recv(rec_inter_data.data(), rec_inter_data.size());

        std::vector<u8> send_inter_data;
        for (u64 i = 0; i < size_oprf; i++)
        {
            // std::cout<<i<<std::endl;
            // input is key of 2 block

            std::vector<u8> recv_x_vec = {rec_inter_data.begin() + 33 * i, rec_inter_data.begin() + 33 * (i + 1)};

            REccPoint x_point(curve);

            x_point.fromBytes(recv_x_vec.data());

            // print_block(x);
            std::vector<u8> b_vec = blocks_to_u8vec(x);

            REccNumber b(curve);

            b.fromBytes(b_vec.data());

            //comment out for comparision
            x_point *= b;

            x_point.toBytes(recv_x_vec.data());

            send_inter_data.insert(send_inter_data.end(), recv_x_vec.begin(), recv_x_vec.end());
        }

        chls[1][0].send(send_inter_data.data(), send_inter_data.size());

        // return the key
        return x;
    }
}


inline std::vector<osuCrypto::block> dh_oprf_batched_multiThreads(AES pubHash, u64 myIdx, std::vector<osuCrypto::block> x, std::vector<std::vector<Channel>> chls, u64 size_oprf,int numThreads)
{
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 1041));
    
    if (myIdx == 0)
    {      
        std::vector<u8> inter_data(size_oprf*33,0);
        vector<thread> threads(numThreads);
        u64 batch_size = size_oprf/numThreads;
        for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
			u64 start, end;
            start = t*batch_size;

            if(t!=numThreads-1){
                end = (t+1)*batch_size;
            }else{
                end = size_oprf;
            }
            REllipticCurve curve;
            for (u64 i = start; i < end; i++)
            {

            std::vector<osuCrypto::block> oprf_value = {x[i]};

            std::vector<osuCrypto::block> H_q(oprf_value.size());

            pubHash.ecbEncBlocks(oprf_value.data(), oprf_value.size(), H_q.data());

            std::vector<u8> hq_vec = block_to_u8vec(H_q[0], 32);

            REccNumber hq_num(curve);

            hq_num.fromBytes(hq_vec.data());

            // hq_num.randomize(prng);

            REccPoint x_point = curve.getGenerator() * hq_num;

            REccNumber a(curve);

            a.randomize(prng);

            // x_point *= a;
            // a.inverse();
            std::vector<u8> inter_vec(33);

            x_point.toBytes(inter_vec.data());

            // inter_data.insert(inter_data.end(), inter_vec.begin(), inter_vec.end());
            std::copy(inter_vec.begin(),inter_vec.end(),inter_data.begin()+(i)*33);

            }

            

	        });
   	    }
	
   	    for(int t = 0;t<numThreads;t++){
            threads[t].join();
   	    }
        

        chls[0][1].send(inter_data.data(), inter_data.size());

        chls[0][1].recv(inter_data.data(), inter_data.size());

        std::vector<osuCrypto::block> result(size_oprf);
        
        for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
			u64 start, end;
            start = t*batch_size;

            if(t!=numThreads-1){
                end = (t+1)*batch_size;
            }else{
                end = size_oprf;
            }
            REllipticCurve curve;

            for (u64 i = start; i < end; i++)
            {
                std::vector<u8> inter_vec = {inter_data.begin() + 33 * i, inter_data.begin() + 33 * (i + 1)};
                REccPoint x_point(curve);
                x_point.fromBytes(inter_vec.data());
                // inverse always outputs 1
                //  a = a.inverse();
                //  std::vector<u8> a_vec(32);
                //  a.toBytes(a_vec.data());
                //  print_u8vec(a_vec);

                // x_point *= a.inverse();

                x_point.toBytes(inter_vec.data());
                inter_vec.erase(inter_vec.begin());
                std::vector<osuCrypto::block> inter_block = u8vec_to_blocks(inter_vec);
                // result.insert(result.end(), inter_block.begin(), inter_block.end());
                // result.push_back(inter_block[0]);
                result[i] = inter_block[0];
            }

            });
   	    }
	
   	    for(int t = 0;t<numThreads;t++){
            threads[t].join();
   	    }

        return result;
    }
    else if (myIdx == 1)
    {
        std::vector<u8> rec_inter_data(33 * size_oprf);
        chls[1][0].recv(rec_inter_data.data(), rec_inter_data.size());
        // REllipticCurve curve;
        std::vector<u8> send_inter_data(size_oprf*33);

        vector<thread> threads(numThreads);
        u64 batch_size = size_oprf/numThreads;
        for(int t = 0;t<numThreads;t++){
		threads[t] = std::thread([&,t](){
			u64 start, end;
            start = t*batch_size;

            if(t!=numThreads-1){
                end = (t+1)*batch_size;
            }else{
                end = size_oprf;
            }
            REllipticCurve curve;
            for (u64 i = start; i < end; i++)
            {

                // input is key of 2 block

                std::vector<u8> recv_x_vec = {rec_inter_data.begin() + 33 * i, rec_inter_data.begin() + 33 * (i + 1)};

                REccPoint x_point(curve);

                x_point.fromBytes(recv_x_vec.data());

                // print_block(x);
                std::vector<u8> b_vec = blocks_to_u8vec(x);

                REccNumber b(curve);

                b.fromBytes(b_vec.data());

                //comment out for comparision
                x_point *= b;

                x_point.toBytes(recv_x_vec.data());

                // send_inter_data.insert(send_inter_data.end(), recv_x_vec.begin(), recv_x_vec.end());
                std::copy(recv_x_vec.begin(),recv_x_vec.end(),send_inter_data.begin()+i*33);
            }
            });
   	    }
	
   	    for(int t = 0;t<numThreads;t++){
            threads[t].join();
   	    }
        
        chls[1][0].send(send_inter_data.data(), send_inter_data.size());

        // return the key
        return x;
    }
}



inline void makeup_test()
{
    for (int i = 0; i < 5; i++)
    {
        Timer timer;
        PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 1041));

        REllipticCurve curve; //(CURVE_25519)

        REccNumber a(curve);

        a.randomize(prng);
        REccPoint x = curve.getGenerator() * a;

        timer.reset();

        u64 setSize = {1 << 16};
        auto start = timer.setTimePoint("start");

        for (u64 i = 0; i < setSize * 1.27; i++)
        {

            x *= a;

            // a.inverse();

            x *= a;
        }

        auto end = timer.setTimePoint("end");

        std::cout << timer << std::endl;
    }
}

inline void oprf_batched_test()
{
    u64 setSize = 1 << 5;
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

    //  set generation
    // first half of same elements and second half of different elements.s

    // ECC Points
    // nParties * setSize * 32 u8 vector
    std::vector<std::vector<std::vector<u8>>>
        inputSet_u8(nParties);
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
        }
    }

    std::cout << inputSet_block[0].size() << std::endl;
    std::vector<osuCrypto::block> oprf(inputSet_u8.size());
    for (u64 i = 0; i < setSize; i++)
    {
        oprf[i] = inputSet_block[0][2 * i];
    }

    // PRNG prngAES(_mm_set_epi32(123, 3434565, 234435, 23987054));
    // std::vector<osuCrypto::block> AES_keys;
    // AES_keys.push_back(prngAES.get<osuCrypto::block>());

    AES pubHash(toBlock(12138));
    REllipticCurve curve; //(CURVE_25519)
    // thread
    std::vector<std::thread> pThrds(nParties);
    for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
    {
        pThrds[pIdx] = std::thread([&, pIdx]()

                                   {
										if(pIdx == 0){
                                            // std::vector<osuCrypto::block> oprf = dh_oprf_batched(pubHash,curve,0,inputSet_block[0],chls,setSize*2);
                                            std::vector<osuCrypto::block> a(1);
                                            a[0] = dh_oprf(pubHash,curve,0,{oprf[0]},chls)[0];
                                            // oprf[i] = dh_oprf(pubHash, curve, 0, {oprf[i]}, chlsoprf)[0];
									   }
									   else if (pIdx == 1){
                                            // std::vector<osuCrypto::block> key = dh_oprf_batched(pubHash,curve,0,inputSet_block[1],chls,setSize*2);
                                            std::vector<osuCrypto::block> key = dh_oprf(pubHash,curve,1,inputSet_block[1],chls);
											
										
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
