#pragma once
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/AES.h>
#include "utl.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include <emp-tool/emp-tool.h>
#include <cryptoTools/Common/Timer.h>
using namespace emp;
using namespace std;
using namespace osuCrypto;


vector<bool> _AeqB(emp::NetIO *io, int party, vector<u64> numbers) {
    size_t share_size = numbers.size();
    vector<Integer> arr1(share_size);
    vector<Integer> arr2(share_size);
    vector<Bit> returns(share_size);

    for (size_t i = 0; i < share_size; i++) 
        arr1[i] = Integer(64, numbers[i], ALICE);
    for (size_t i = 0; i < share_size; i++) 
        arr2[i] = Integer(64, numbers[i], BOB);
    for (size_t i = 0; i < share_size; i++) 
        returns[i] = (arr1[i] == arr2[i]);
    

    vector<bool> bS(share_size);
    for(size_t i = 0; i < share_size; ++i)
        bS[i] = getLSB(returns[i].bit);

    return bS;
}

void gc_test(){
    //thread
    u64 setSize = {1<<20};
    setSize*=1.27;
    std::cout<<setSize<<std::endl;
    PRNG prng(_mm_set_epi32(4253465, 3431235, 232324, 123456));
    std::vector<osuCrypto::block> a;
    std::vector<u64> num(setSize);
    for(int i = 0;i<setSize;i++){
        a.push_back(prng.get<osuCrypto::block>());
        memcpy(&num[i], &a[i], sizeof(u64));
    }

    Timer timer;
	timer.reset();



	auto start = timer.setTimePoint("start");
	std::vector<std::thread>  pThrds(2);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{   
		pThrds[pIdx] = std::thread([&, pIdx]() {
            int comm_recv=0;
            int comm_sent=0;    
			int port = 1000;
            int party = pIdx;

            emp::NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", 6000);

            setup_semi_honest(io, party);

	        auto z = _AeqB(io,party, num);
            std::cout<<z[1]<<std::endl;
            comm_recv += io->total_recv;
	        comm_sent += io->total_sent;
            std::cout << "party #" << pIdx << "\t GC Comm Send: " << (comm_sent / std::pow(2.0, 20)) << " MB" << std::endl;
        	std::cout << "party #" << pIdx << "\t GC Recv Recv: " << (comm_recv / std::pow(2.0, 20)) << " MB" << std::endl;

            delete io;

		});
	}
    
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();
    auto end = timer.setTimePoint("end");
    std::cout<<timer<<std::endl;
}
