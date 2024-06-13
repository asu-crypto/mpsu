#include <iostream>
#include "psu.h"
#include "gbf.h"
#include "gc.h"
#include "ot_mpsu.h"
#include "oprf_mpsu.h"
#include "libOTe/libOTe_Tests/OT_Tests.h"
#include "hash_test.h"
#include "chls_test.h"
#include "oprf_batch_mpsu.h"

using namespace osuCrypto;

int main(void){


    mpsu_test();
    // makeup_test();
    // sspmt_test();
    // oprf_batched_test();
    // channel_delay_test();
    //rpir_framework_test();
    // ecc_channel_test();
    // convert_test();
    // oprf_test();
    // gc_test();
    //OtExt_Iknp_Test();
    // ot_test();
    //hash_test();


    return 0;
}
