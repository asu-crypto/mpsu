#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "utl.h"

namespace osuCrypto
{

    class CuckooTable
    {
    public:

		std::vector<block> items;
        std::vector<u8> hashIds;
        std::vector<u64> item_idx;

        u64 numBins,numHashes;
        u64 tryLimit = 200;
        u64 numStash = 0;

        void init(double scalar, u64 numBalls,u64 num_hash){
            numBins = scalar * numBalls;
            std::vector<block> z(numBins,toBlock(u64(0)));
            items = z;
            std::vector<u8> h(numBins,-1);
            hashIds = h;
            std::vector<u64> idx(numBins,-1);
            item_idx = idx;
            numHashes = num_hash;
        }

        void insertItem(block element,u64 idx){

            u64 try_count = 0;
            u8 curHash = 0;
            while(true){
                u64 cur_addr = get_hash(element,curHash,numBins);
                //swap into the bin
                block temp_block = element;
                u8 temp_hashid = curHash;
                u64 temp_idx = idx;
                element = items[cur_addr];
                curHash = hashIds[cur_addr];
                idx = item_idx[cur_addr];
                items[cur_addr] = temp_block;
                hashIds[cur_addr] = temp_hashid;
                item_idx[cur_addr] = temp_idx;
                

                if(element==toBlock(u64(0))){
                    //empty bin, insert seccess
                    return;
                }else{
                    if(try_count<tryLimit){

                         //try a different hash
                         curHash = (curHash + 1) % numHashes;
                         try_count++;
                    }else{
                        numStash++;
                        return;
                    }
                }
            }
        }

        void padGlobalItems(PRNG& prng){

            for (u64 i = 0;i<items.size();i++){
                if(items[i]==toBlock(u64(0))){
                    items[i]=prng.get<block>();
                }
            }

            return;
        }


        void print_table(){
            for(u64 i = 0; i < items.size(); i++){
                if(items[i]==toBlock(u64(0))){
                    std::cout<<"-1"<<std::endl;
                }else{
                    std::cout<<items[i]<<" "<<item_idx[i]<<std::endl;
                }
                std::cout<<"-----------------------------------"<<std::endl;
            }
        }


    };

}
