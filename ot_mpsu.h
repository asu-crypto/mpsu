#pragma once
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>

#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

// #include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
// #include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"


#include <thread>
#include <vector>
#include <random>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h> 
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/block.h>



using namespace osuCrypto;

    // void ot_test(){
        
    //     auto sockets = cp::LocalAsyncSocket::makePair();

    //     PRNG prng0(osuCrypto::block(4253465, 3434565));
    //     PRNG prng1(osuCrypto::block(42532335, 334565));

    //     u64 numOTs = 200;

    //     std::vector<osuCrypto::block> recvMsg(numOTs), baseRecv(128);
    //     std::vector<std::array<osuCrypto::block, 2>> sendMsg(numOTs), baseSend(128);
    //     BitVector choices(numOTs), baseChoice(128);
    //     choices.randomize(prng0);
    //     baseChoice.randomize(prng0);

    //     prng0.get((u8*)baseSend.data()->data(), sizeof(osuCrypto::block) * 2 * baseSend.size());


    //     for (u64 i = 0; i < 128; ++i)
    //     {   
    //         baseRecv[i] = baseSend[i][baseChoice[i]];
    //     }

    //     for (u64 i = 0;i < numOTs; i++){
    //         sendMsg[i][0] = prng1.get<osuCrypto::block>();
    //         sendMsg[i][1] = prng1.get<osuCrypto::block>();
    //     }
    //     std::cout<<"123"<<std::endl;
    //     IknpOtExtSender sender;
    //     IknpOtExtReceiver recv;

        
    //     recv.setBaseOts(baseSend);
    //     //recv.receive(choices, recvMsg, prng0, sockets[0]);
    //     sender.setBaseOts(baseRecv, baseChoice);
    //     //sender.send(sendMsg, prng1, sockets[1]);
    //     macoro::sync_wait(macoro::when_all_ready(
    //         recv.receive(choices, recvMsg, prng0, sockets[0]),
    //         sender.send(sendMsg, prng1, sockets[1])
    //     ));

    //     std::cout<<sendMsg[0][0]<<std::endl;
    //     std::cout<<sendMsg[0][1]<<std::endl;
    //     std::cout<<choices[0]<<std::endl;
    //     std::cout<<recvMsg[0]<<std::endl;        
    //     }

        void ot_test2(){
        IOService ios;
		Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
		Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
		Channel senderChannel = ep1.addChannel();
		Channel recvChannel   = ep0.addChannel();

		PRNG prng0(osuCrypto::block(4253465, 3434565));
		PRNG prng1(osuCrypto::block(42532335, 334565));

		u64 numOTs = 200;

		std::vector<osuCrypto::block> recvMsg(numOTs), baseRecv(128);
		std::vector<std::array<osuCrypto::block, 2>> sendMsg(numOTs), baseSend(128);
		BitVector choices(numOTs), baseChoice(128);
		choices.randomize(prng0);
		baseChoice.randomize(prng0);

		prng0.get((u8*)baseSend.data()->data(), sizeof(osuCrypto::block) * 2 * baseSend.size());
		for (u64 i = 0; i < 128; ++i)
		{
			baseRecv[i] = baseSend[i][baseChoice[i]];
		}

		IknpOtExtSender sender;
		IknpOtExtReceiver recv;

		std::thread thrd = std::thread([&]() {
			recv.setBaseOts(baseSend);
			recv.receive(choices, recvMsg, prng0, recvChannel);
		});

        std::cout<<sendMsg[0][0]<<std::endl;
        std::cout<<sendMsg[0][1]<<std::endl;

		sender.setBaseOts(baseRecv, baseChoice);
		sender.send(sendMsg, prng1, senderChannel);
        std::cout<<sendMsg[0][0]<<std::endl;
        std::cout<<sendMsg[0][1]<<std::endl;
        std::cout<<choices[0]<<std::endl;
        std::cout<<recvMsg[0]<<std::endl;    
		thrd.join();


        }


        
void psu_ot(std::vector<osuCrypto::block> inputSet, u64 nParties, u64 myIdx, u64 setSize, std::vector<std::vector<Channel>> chls) {
	int n = 100;
	if (myIdx == 0) {
		PRNG prng(sysRandomSeed());
		IknpOtExtReceiver recver;

		// Choose which messages should be received.
		BitVector choices(n);
		choices[0] = 1;

		// Receive the messages
		std::vector<osuCrypto::block> messages(n);
		recver.receiveChosen(choices, messages, prng, chls[0][1]);

		// messages[i] = sendMessages[i][choices[i]];
		std::cout << messages[0] << std::endl;
	}
	else if (myIdx == 1) {
		PRNG prng(sysRandomSeed());
		IknpOtExtSender sender;

		// Choose which messages should be sent.
		std::vector<std::array<osuCrypto::block, 2>> sendMessages(n);
		sendMessages[0] = { toBlock(54), toBlock(33) };

		std::cout << sendMessages[0][0] << std::endl;
		std::cout << sendMessages[0][1] << std::endl;

		// Send the messages.
		sender.sendChosen(sendMessages, prng, chls[1][0]);
	}
	
}


void ot_test() {
	u64 setSize = 1 << 1;
	// u64 psiSecParam = 40;
	// u64 bitSize = 128;
	u64 nParties = 2;
	
	//Create Channels
	IOService ios(0);

	auto ip = std::string("127.0.0.1");

	std::string sessionHint = "psu";

	std::vector<std::vector<Session>> ssns(nParties, std::vector<Session>(nParties));
	std::vector<std::vector<Channel>> chls(nParties, std::vector<Channel>(nParties));

	for (u64 i = 0; i < nParties; i++) {
		for (u64 j = 0; j < nParties; j++) {
			if (i < j) {
				u32 port = 1100 + j * 100 + i;
				std::string serversIpAddress = ip + ':' + std::to_string(port);
				ssns[i][j].start(ios, serversIpAddress, SessionMode::Server, sessionHint);

				chls[i][j] = ssns[i][j].addChannel();
				//ep[i].start(ios, "localhost", port, true, name); //channel bwt i and pIdx, where i is receiver
			}
			else if (i > j) {
				u32 port = 1100 + i * 100 + j;
				std::string serversIpAddress = ip + ':' + std::to_string(port);
				ssns[i][j].start(ios, serversIpAddress, SessionMode::Client, sessionHint);
				chls[i][j] = ssns[i][j].addChannel();
				//ep[i].start(ios, "localhost", port, false, name); //channel bwt i and pIdx, where i is sender
			}
		}
	}

	//set generation
	//first half of same elements and second half of different elements.s
	std::vector<std::vector<osuCrypto::block>> inputSet(nParties, std::vector<osuCrypto::block>(setSize));
	for (u64 i = 0; i < nParties; i++) {
		PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987054));
		PRNG prngDiff(_mm_set_epi32(4253465, 3434565, 234423, i));
		for (u64 j = 0; j < setSize; j++) {
			if (j < setSize / 2) {
				inputSet[i][j] = prngSame.get<osuCrypto::block>();
				//std::cout <<"input of " << myIdx << " : " << hex << inputSet[j] << std::endl;
			}
			else {
				inputSet[i][j] = prngDiff.get<osuCrypto::block>();
				//std::cout << "input of " << myIdx << " : " << hex <<inputSet[j] << std::endl;
			}
		}

		/*std::cout << IoStream::lock;

		std::cout << "party " << i << " break point 1" << std::endl;
		print_block(inputSet[i]);

		std::cout << IoStream::unlock;*/

	}




	std::vector<std::thread>  pThrds(nParties);
	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
	{
		pThrds[pIdx] = std::thread([&, pIdx]() {
			psu_ot(inputSet[pIdx], nParties, pIdx, setSize, chls);
			});
	}

	for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
		pThrds[pIdx].join();




	//Close channels
	for (u64 i = 0; i < nParties; i++) {
		for (u64 j = 0; j < nParties; j++) {
			if (i != j) {
				chls[i][j].close();
			}
		}
	}

	for (u64 i = 0; i < nParties; i++) {
		for (u64 j = 0; j < nParties; j++) {
			if (i != j) {
				ssns[i][j].stop();
			}
		}
	}

	ios.stop();
}



