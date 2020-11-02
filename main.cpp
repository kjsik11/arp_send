#include "main.h"

using namespace std;


int main(int argc,char *argv[]){
    if(argc!=0){
        printf("input value");
    }
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *fp;

    if ( (fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf) ) == NULL)
        {
            fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Pcap\n", argv[1]);
            return -1;
        }

    //ETH PACKET
    eth_packet eth;
    eth.type=0x0608;

    //ARP_PACKET
    arp_packet arp;
    arp.h_type=0x0100;
    arp.p_type=0x0008;
    arp.h_size=0x06;
    arp.p_size=0x04;
    arp.opcode=0x0100;


//input mac
    input_mac(eth.dmac,"ff:ff:ff:ff:ff:ff");
    input_mac(eth.smac,"70:5d:cc:f4:82:d1");
    input_mac(arp.smac,"70:5d:cc:f4:82:d1");
    input_mac(arp.tmac,"00:00:00:00:00:00");
    input_ip(arp.sip,"192.168.123.102");
    input_ip(arp.tip,"192.168.123.254");


    //MAKE ARP PACKET
    PACKET pk;
    pk.e=eth;
    pk.a=arp;


    //SEND PACKET

    int res=pcap_sendpacket(fp,reinterpret_cast<const u_char*>(&pk),60);
    if (res==0){
        fprintf(stderr,"pcap_sendpacket return %d error=%s\n",res,pcap_geterr(fp));
    }
}

