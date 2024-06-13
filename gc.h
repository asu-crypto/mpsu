#pragma once
// #include "cryptoTools/Crypto/Curve.h"
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/AES.h>

// #include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
// #include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include "gbf.h"
#include "utl.h"
#include "eccConvert.h"

#include "emp-sh2pc/emp-sh2pc.h"
#include <emp-tool/emp-tool.h>
using namespace emp;
using namespace std;
using namespace osuCrypto;

// Based on Goubin theorem
// vector<emp::Bit> _AgeqB(emp::NetIO *io, int party_id, long long number)
// {
//     // return 2 shares of x \geq y
//     emp::Integer A(128, number, ALICE); // x
//     emp::Integer r(128, -number, BOB);  //-y
//     emp::Integer u(128, 0, ALICE);
//     for (int i = 0; i < 128; i++)
//     {
//         u = (u & (A ^ r) ^ (A & r));
//         u = u + u;
//     }
//     vector<emp::Integer> z = {((A ^ u)), ((r))}; // z0 xor z1 = x-y

//     return {(z[0] >> 127).bits[0], !(z[1] >> 127).bits[0]};
// }

// bool _AeqB(emp::NetIO *io, int party_id, long long number)
// {
//     Integer a(64, number, ALICE);
//     Integer b(64, number, BOB);
//     Bit res = a==b;
//     return getLSB(res.bit);
// }

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
// vector<emp::Bit> _AeqB(emp::NetIO *io, int party_id, long long number){
//    if(true){
//        Integer a(128, number, ALICE);
//        Integer b(128, number, BOB);
//        Bit res = (b == a);
//        PRG prg;
//        bool r_;
//        prg.random_data(&r_,sizeof(bool));
//        Bit r2(r_);
//        Bit r1 = res^r2;
//        bool r1_ = r1.reveal<bool>();
//        if(party_id==0)
//            cout << r_ << " " << r1_ <<endl;
//        return {r1, r2};
//    }else{
//        auto x = _AgeqB(io, party_id, number);
//        auto y = _AgeqB(io, party_id, -number);
//        // auto z1 = (x[0]&y[0])^(x[0]&y[1]);
//        // auto z2 = (x[1]&y[0])^(x[1]&y[1]);
//        emp::PRG prg;
//        bool r_;
//        prg.random_data(&r_,1);
//        emp::Bit r(r_);
//        //simply doing secand
//        emp::Bit r2 = (r^(x[0]&y[1]))^(x[1]&y[0]);
//        emp::Bit z1 = r^(x[0]&y[0]);
//        emp::Bit z2 = r2^(x[1]&y[1]);
//        return {z1,z2};
//    }
// }



// vector<bool> _AeqB(emp::NetIO *io, int party_id, long long number)
// {
//     // if (true)
//     // {
//         Integer a(64, number, ALICE);
//         Integer b(64, number, BOB);
//         Bit res = 1;
//         for (int i = 0; i < 64; i++)
//         {
//             res = res & (a.bits[i] == b.bits[i]);
//             // std::cout<<i<<std::endl;
//         }

//         PRG prg;
//         bool r_;
//         prg.random_data(&r_, sizeof(bool));
//         // Bit r2(r_);
//         bool r1 = res.reveal<bool>() ^ r_;
//         // std::vector<Bit> r = {r1,r2}

//         return {r1, r_};

//         //    Integer a(64, number, ALICE);
//         //    Integer b(64, number, BOB);
//         //    Bit res = (b == a);
//         //    PRG prg;
//         //    bool r_;
//         //    prg.random_data(&r_,sizeof(bool));
//         //    Bit r2(r_);
//         //    Bit r1 = res^r2;
//         //    bool r1_ = r1.reveal<bool>();
//         //    if(party_id==0)
//         //        cout << r_ << " " << r1_ <<endl;
//         //    return {r1, r2};
//     // }
//     // else
//     // {
//     //     auto x = _AgeqB(io, party_id, number);
//     //     auto y = _AgeqB(io, party_id, -number);
//     //     // auto z1 = (x[0]&y[0])^(x[0]&y[1]);
//     //     // auto z2 = (x[1]&y[0])^(x[1]&y[1]);
//     //     emp::PRG prg;
//     //     bool r_;
//     //     prg.random_data(&r_, 1);
//     //     emp::Bit r(r_);
//     //     // simply doing secand
//     //     emp::Bit r2 = (r ^ (x[0] & y[1])) ^ (x[1] & y[0]);
//     //     emp::Bit z1 = r ^ (x[0] & y[0]);
//     //     emp::Bit z2 = r2 ^ (x[1] & y[1]);
//     //     return {z1, z2};
//     // }
// }

void gc_test(){
    //thread
    u64 setSize = {1<<8};
    setSize*=1.27;
    std::cout<<setSize<<std::endl;
    PRNG prng(_mm_set_epi32(4253465, 3431235, 232324, 123456));
    std::vector<osuCrypto::block> a;
    std::vector<u64> num(setSize);
    for(int i = 0;i<setSize;i++){
        a.push_back(prng.get<osuCrypto::block>());
        memcpy(&num[i], &a[i], sizeof(u64));
    }
    // std::cout<<"1"<<std::endl;
    Timer timer;
	timer.reset();

	auto start = timer.setTimePoint("start");
	std::vector<std::thread>  pThrds(2);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{   
        // PRNG prng(_mm_set_epi32(4253465, 3431235, 232324, 123456));
		pThrds[pIdx] = std::thread([&, pIdx]() {
			int port = 1000;
            int party = pIdx;
            // long long num = pIdx+1;
            // std::cout<<pIdx<<std::endl;
            // emp::NetIO *io = new NetIO("127.0.0.1", 6000 );
            emp::NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", 6000);
            // std::cout<<pIdx<<std::endl;

            setup_semi_honest(io, party);

	        auto z = _AeqB(io,party, num);
            std::cout<<z[1]<<std::endl;
            delete io;

		});
	}
    
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();
    auto end = timer.setTimePoint("end");
    std::cout<<timer<<std::endl;
}

// int main(int argc, char** argv) {
// 	int port, party;
// 	parse_party_and_port(argv, &party, &port);
// 	long long num = 20;
// 	if(argc > 3)
// 		num = atoll(argv[3]);
// 	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
// 	setup_semi_honest(io, party);
// 	auto z = _AeqB(io,party, num);
// 	bool bS = z[0].reveal<bool>();
// 	bool bR = z[1].reveal<bool>();
// 	cout << "bs "<<bS <<endl;
// 	cout << "br "<<bR <<endl;

// 	delete io;
// 	if (bS^bR){
// 		cout << "Alice = Bob"<<endl;
// 	}else{
// 		cout << "Alice =/= Bob" << endl;
// 	}
// }
