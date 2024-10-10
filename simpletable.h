#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "utl.h"
namespace osuCrypto
{   
    // float binomial_co(i32(n),i32(k)){
    //     if(k == 1 || k ==n){
    //         return 1;
    //     }else{
    //         return binomial_co(n-1,k-1)+binomial_co(n-1,k);
    //     }
    // }

    // double getBinOverflowProb(u64 numBins, u64 numBalls, u64 getBinSize, double epsilon = 0.1)
    // {
    //     if (numBalls <= getBinSize)
    //         return std::numeric_limits<double>::max();

    //     if (numBalls > std::numeric_limits<i32>::max())
    //     {
    //         auto msg = ("boost::math::binomial_coefficient(...) only supports " + std::to_string(sizeof(unsigned) * 8) + " bit inputs which was exceeded." LOCATION);
    //         std::cout << msg << std::endl;
    //         throw std::runtime_error(msg);
    //     }

    //     //std::cout << numBalls << " " << numBins << " " << binSize << std::endl;
    //     // typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_bin_float<16>> T;
    //     // T sum = 0.0;
    //     // T sec = 0.0;// minSec + 1;
    //     // T diff = 1;

    //     float sum = 0.0;
    //     float sec = 0.0;// minSec + 1;
    //     float diff = 1;
    //     u64 i = getBinSize + 1;


    //     while (diff > (float)epsilon && numBalls >= i /*&& sec > minSec*/)
    //     {   
    //         std::cout<<sum<<std::endl;
    //         sum += numBins * binomial_co(i32(numBalls), i32(i))
    //             * pow((1.0) / numBins, i) * pow(1 - (1.0) / numBins, numBalls - i);

    //         //std::cout << "sum[" << i << "] " << sum << std::endl;

    //         double sec2 = log2(sum);
    //         diff = abs(sec - sec2);
    //         //std::cout << diff << std::endl;
    //         sec = sec2;

    //         i++;
    //     }

    //     return std::max<double>(0, (double)-sec);
    // }

    // u64 get_bin_size(u64 numBins, u64 numBalls, u64 statSecParam)
    // {

    //     auto B = std::max<u64>(1, numBalls / numBins);

    //     double currentProb = getBinOverflowProb(numBins, numBalls, B);
    //     u64 step = 1;

    //     bool doubling = true;

    //     while (currentProb < statSecParam || step > 1)
    //     {   
    //         std::cout<<currentProb<<std::endl;
    //         if (!step)
    //             throw std::runtime_error(LOCATION);


    //         if (statSecParam > currentProb)
    //         {
    //             if (doubling) step = std::max<u64>(1, step * 2);
    //             else          step = std::max<u64>(1, step / 2);

    //             B += step;
    //         }
    //         else
    //         {
    //             doubling = false;
    //             step = std::max<u64>(1, step / 2);
    //             B -= step;
    //         }
    //         currentProb = getBinOverflowProb(numBins, numBalls, B);
    //     }

    //     return B;
    // }


    // //template<unsigned int N = 16>
    // double getBinOverflowProb(u64 numBins, u64 numBalls, u64 getBinSize, double epsilon = 0.0001)
    // {
    //     if (numBalls <= getBinSize)
    //         return std::numeric_limits<double>::max();

    //     if (numBalls > std::numeric_limits<i32>::max())
    //     {
    //         auto msg = ("boost::math::binomial_coefficient(...) only supports " + std::to_string(sizeof(unsigned) * 8) + " bit inputs which was exceeded." LOCATION);
    //         std::cout << msg << std::endl;
    //         throw std::runtime_error(msg);
    //     }

    //     //std::cout << numBalls << " " << numBins << " " << binSize << std::endl;
    //     typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_bin_float<16>> T;
    //     T sum = 0.0;
    //     T sec = 0.0;// minSec + 1;
    //     T diff = 1;
    //     u64 i = getBinSize + 1;


    //     while (diff > T(epsilon) && numBalls >= i /*&& sec > minSec*/)
    //     {
    //         sum += numBins * boost::math::binomial_coefficient<T>(i32(numBalls), i32(i))
    //             * boost::multiprecision::pow(T(1.0) / numBins, i) * boost::multiprecision::pow(1 - T(1.0) / numBins, numBalls - i);

    //         //std::cout << "sum[" << i << "] " << sum << std::endl;

    //         T sec2 = boost::multiprecision::log2(sum);
    //         diff = boost::multiprecision::abs(sec - sec2);
    //         //std::cout << diff << std::endl;
    //         sec = sec2;

    //         i++;
    //     }

    //     return std::max<double>(0, (double)-sec);
    // }

    // u64 SimpleIndex::get_bin_size(u64 numBins, u64 numBalls, u64 statSecParam)
    // {

    //     auto B = std::max<u64>(1, numBalls / numBins);

    //     double currentProb = getBinOverflowProb(numBins, numBalls, B);
    //     u64 step = 1;

    //     bool doubling = true;

    //     while (currentProb < statSecParam || step > 1)
    //     {
    //         if (!step)
    //             throw std::runtime_error(LOCATION);


    //         if (statSecParam > currentProb)
    //         {
    //             if (doubling) step = std::max<u64>(1, step * 2);
    //             else          step = std::max<u64>(1, step / 2);

    //             B += step;
    //         }
    //         else
    //         {
    //             doubling = false;
    //             step = std::max<u64>(1, step / 2);
    //             B -= step;
    //         }
    //         currentProb = getBinOverflowProb(numBins, numBalls, B);
    //     }

    //     return B;
    // }


    class SimpleTable
    {
    public:

		std::vector<std::vector<block>> items;

        u64 numBins,numHashes;

		u64 getMaxBinSize(){
            u64 maxBinSize = 0;
            for(u64 i = 0;i<items.size();i++){
                if(items[i].size()>maxBinSize){
                    maxBinSize = items[i].size();
                }
            }
            return maxBinSize;
        }

		void init(double scalar, u64 numBalls,u64 num_hash){
            numBins = scalar * numBalls;
            items.resize(numBins);
            numHashes = num_hash;
        }

        void insertItems(block element){
            for(u8 i = 0;i<numHashes;i++){
                u64 address = get_hash(element,i,numBins);
                items[address].push_back(element);
            }

            return;
            
        }
    

    	void padGlobalItems(PRNG& prng,u64 maxNum){

            for (u64 i = 0;i<items.size();i++){
                for (u64 j = items[i].size();j<maxNum;j++){
                    //std::cout<<"1"<<std::endl;
                    items[i].push_back(prng.get<block>());
                }
            }

            return;
        }

        void print_table(){
            for(u64 i = 0;i<items.size();i++){
                if(items[i].size()==0){
                    std::cout<<"-1"<<std::endl;
                }else{
                    print_block(items[i]);
                }
                std::cout<<"-----------------------------------"<<std::endl;
            }
        }

        void clear_table(){
            for(u64 i = 0;i<items.size();i++){
                if(items[i].size()!=0){
					items[i].resize(0);
				}
            }
        }

    };

}
