#pragma once
#include <set>
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Common/config.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "utl.h"
//#include "psu.h"

using namespace osuCrypto;


inline void GbfEncode(const std::vector<std::pair<block, block>> key_values, std::vector<block>& garbledBF)
{	

	u64 setSize = key_values.size();

	u64 mBfBitCount = okvsLengthScale * setSize;
	
	u64 numHashFunctions = okvsHashFunctions;

	std::vector<AES> mBFHasher(numHashFunctions);
	for (u64 i = 0; i < mBFHasher.size(); ++i)
		mBFHasher[i].setKey(_mm_set1_epi64x(i));

	
	garbledBF.resize(mBfBitCount,ZeroBlock);
	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	std::vector<std::set<u64>> idxs(setSize);
	for (u64 i = 0; i < setSize; ++i)
	{	
		u64 firstFreeIdx(-1);
		block sum = ZeroBlock;

		//std::cout << "input[" << i << "] " << inputs[i] << std::endl;

		//idxs.clear();
		for (u64 hashIdx = 0; hashIdx < mBFHasher.size(); ++hashIdx)
		{

			block hashOut = mBFHasher[hashIdx].ecbEncBlock(key_values[i].first);
			u64& idx = *(u64*)&hashOut;
			//std::cout<<idx<<std::endl;
			idx %= mBfBitCount;
			idxs[i].emplace(idx);

			//std::cout << idx << " ";
		}
		//std::cout << "\n";
		for (auto idx : idxs[i])
		{	//std::cout<<idx<<std::endl;
			if (eq(garbledBF[idx], ZeroBlock))
			{
				if (firstFreeIdx == u64(-1))
				{
					firstFreeIdx = idx;
					//std::cout << "firstFreeIdx: " << firstFreeIdx << std::endl;

				}
				else
				{
					garbledBF[idx] = _mm_set_epi64x(idx, idx);
					//	std::cout << coefficients[idx] <<"\n";
					sum = sum ^ garbledBF[idx];
					//std::cout << idx << " " << coefficients[idx] << std::endl;
				}
			}
			else
			{
				sum = sum ^ garbledBF[idx];
				//std::cout << idx << " " << coefficients[idx] << std::endl;
			}
		}

		if(firstFreeIdx!=u64(-1))
			garbledBF[firstFreeIdx] = sum ^ key_values[i].second;
		//std::cout << firstFreeIdx << " " << coefficients[firstFreeIdx] << std::endl;
		//std::cout << test << "\n";
		//std::cout << "sender " << i << " *   " << coefficients[firstFreeIdx] << "    " << firstFreeIdx << std::endl;
	}

	//filling random for the rest
	for (u64 i = 0; i < garbledBF.size(); ++i)
		if (eq(garbledBF[i], ZeroBlock))
			garbledBF[i] = prng.get<block>();

	/*std::cout << IoStream::lock;
	for (u64 i = 0; i < 5; i++)
		std::cout << coefficients[i] << " - GbfEncode - " << i << std::endl;
	std::cout << IoStream::unlock;*/
}

inline  void GbfEncode(const std::vector<block> setKeys, const std::vector<block> setValues, std::vector<block>& garbledBF)
{
	std::vector<std::pair<block, block>> key_values(setKeys.size());

	for (u64 i = 0; i < key_values.size(); ++i)
	{
		memcpy((u8*)&key_values[i].first, (u8*)&setKeys[i], sizeof(block));
		memcpy((u8*)&key_values[i].second, (u8*)&setValues[i], sizeof(block));
	}
	//std::cout << setValues[0] << " vs " << key_values[0].second << "\n";

	GbfEncode(key_values, garbledBF);
}

inline  void GbfDecode(const std::vector<block> garbledBF, const std::vector<block> setKeys, std::vector<block>& setValues)
{
	u64 setSize = setKeys.size();
	u64 mBfBitCount = garbledBF.size();
	u64 numHashFunctions = okvsHashFunctions;

	std::vector<AES> mBFHasher(numHashFunctions);
	for (u64 i = 0; i < mBFHasher.size(); ++i)
		mBFHasher[i].setKey(_mm_set1_epi64x(i));

	setValues.resize(setSize);

	for (u64 i = 0; i < setSize; ++i)
	{
		//std::cout << "mSetY[" << i << "]= " << mSetY[i] << std::endl;
		//	std::cout << mSetX[i] << std::endl;

		std::set<u64> idxs;

		for (u64 hashIdx = 0; hashIdx < mBFHasher.size(); ++hashIdx)
		{
			block hashOut = mBFHasher[hashIdx].ecbEncBlock(setKeys[i]);
			u64& idx = *(u64*)&hashOut;
			idx %= mBfBitCount;
			idxs.emplace(idx);
		}
		setValues[i] = ZeroBlock;
		for (auto idx : idxs)
		{	//std::cout<<idx<<std::endl;
			//std::cout << idx << " " << coefficients[idx] << std::endl;
			setValues[i] = setValues[i] ^ garbledBF[idx];
		}

		//if (i == 0) //for test
		//	std::cout << mSetY[0] << "\t vs \t" << sum << std::endl;
	}

}

inline void GbfTest()
{
	std::cout << " ============== GbfTest ==============\n";

	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

	std::vector<std::pair<block, block>> key_values(128);
	std::vector<block> setKeys(128);
	std::vector<block> setValues(128);
	std::vector<block> setValuesOut(128);

	for (u64 i = 0; i < key_values.size(); ++i)
	{
		key_values[i].first = prng.get<block>();
		key_values[i].second = prng.get<block>();
		setKeys[i] = key_values[i].first;
		setValues[i] = key_values[i].second;
	}

	std::vector<block> garbledBF;
	//GbfEncode(key_values, coefficients);
	GbfEncode(setKeys, setValues, garbledBF);
	//std::cout << garbledBF.size() << std::endl;


	/*for (size_t i = 0; i < 10; i++)
		std::cout << garbledBF[i] << "\n";*/
	


	GbfDecode(garbledBF, setKeys, setValuesOut);

	for (size_t i = 0; i < 128; i++)
	{
		if(memcmp((u8*)&setValues[i], (u8*)&setValuesOut[i], sizeof(block)) == 1)
			std::cout << setValues[i] << " vs " << setValuesOut[i] << "\n";

	}
	std::cout << " ============== done ==============\n";

}

