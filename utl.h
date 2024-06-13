#pragma once

#define okvsHashFunctions  3
#define okvsLengthScale  1.27

#define rbOkvsEpsillon 0.1


using namespace osuCrypto;

inline void print_block(std::vector<osuCrypto::block> a) {

	for (u64 i = 0; i < a.size(); i++) {
		std::cout << a[i] << std::endl;
	}


}

inline void print_u8vec(std::vector<u8> a) {

	for (u64 i = 0; i < a.size(); i++) {
		std::cout << std::hex<< unsigned(a[i]);
	}

	std::cout << std::endl;

}

inline u64 get_hash(osuCrypto::block& element, u8& hashIdx, u64& num_bins)
        {
            u8* ptr = (u8*)&element;
            ptr += 2 * hashIdx;

            u64 h = *(u64*)ptr;
            return h % num_bins;
        }
