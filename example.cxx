// build: cl /std:c++17 /O2 example.cxx

#include "rcf.hxx"
#include <cstdio>
// replace this with your own thing
static void send_to_server(const void* data, size_t len) {
    std::printf("[server] blob len=%zu\n", len);
    const auto* b = static_cast<const rcf::attestation_blob*>(data);
    std::printf("[server] version=%u seed=%llx code=%llx self=%llx\n",
        b->version,
        (unsigned long long)b->seed,
        (unsigned long long)b->code_digest,
        (unsigned long long)b->self_digest);
}
// we create two seperate functions, one for sending a string data (this one) and the previous one sending an object
static void report_to_server(const char* tag, uint64_t digest) { 
    std::printf("[server] %s digest=%llx\n", tag, (unsigned long long)digest);
}

int main() {
    if (!rcf::attest_init()) {
        std::printf("[rcf] init failed\n");
        return 1;
    }
    std::printf("[rcf] baseline captured\n");

    // if you're actually using this add this in a thread that checks every 30ish seconds on low priority (or default).
    for (int i = 0; i < 3; ++i) {
        bool ok = false;
        uint64_t d = rcf::attest_verify(&ok);
        std::printf("[rcf] verify #%d ok=%d digest=%llx\n",
            i, (int)ok, (unsigned long long)d);

        if (!ok) {
        
            report_to_server("code_integrity_fail", d); // ensure this function is NOT async or you'll crash before sending data
            __fastfail(0); // cant hook this can ya :p
        }

        bool self_ok = false;
        uint64_t sd = rcf::attest_verify_self(&self_ok);
        std::printf("[rcf] self_ok=%d self=%llx\n",
            (int)self_ok, (unsigned long long)sd);

        if (i == 2) {
            rcf::attestation_blob blob{};
            if (rcf::attest_blob(&blob)) {
                send_to_server(&blob, sizeof(blob));
            } else {
                std::printf("[rcf] blob failed local check\n");
            }
        }
    }

    std::printf("[rcf] done\n");
    return 0;
}
