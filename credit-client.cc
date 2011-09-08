#include "fw/runner.hh"
#include "credit-client.hh"

using namespace fw;

static void f(credit_client &cc) {
    packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    inet_pton(AF_INET, "127.0.1.10", pkt.key);
    pkt.value = 1;
    cc.send_packet(pkt);
    pkt.value = 1;
    cc.send_packet(pkt);
    cc.close();
}

int main(int argc, char *argv[]) {
    runner::init();
    credit_client cc("localhost");
    task::spawn(boost::bind(f, boost::ref(cc)));
    return runner::main();
}
