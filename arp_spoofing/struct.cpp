#include <stdio.h>
#include <pcap.h>


struct eth_packet{
    u_int8_t dmac[6];
    u_int8_t smac[6];
    u_int16_t type;
};

struct arp_packet{
    u_int16_t h_type;
    u_int16_t p_type;
    u_int8_t h_size;
    u_int8_t p_size;
    u_int16_t opcode;
    u_int8_t smac[6];
    u_int8_t sip[4];
    u_int8_t tmac[6];
    u_int8_t tip[4];
    u_int8_t pad[18];
};

struct PACKET{
    eth_packet e;
    arp_packet a;
};
