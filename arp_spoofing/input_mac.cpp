#pragma once
#include <stdio.h>
#include <pcap.h>
static void input_mac(u_int8_t *mac,char str[]){
    int temp=0;
    for(int i=0;i<6;i++){
        int tmp[2];
        tmp[0]=str[temp++];
        tmp[1]=str[temp++];
        for(int j=0;j<2;j++){
            if(48<=tmp[j]&&tmp[j]<=57){
                if(j==0) tmp[j]=(tmp[j]-48)*16;
                else tmp[j]-=48;
            }
            else if(65<=tmp[j]&&tmp[j]<=70) {
                if(j==0) tmp[j]=(tmp[j]-55)*16;
                else tmp[j]-=55;
            }
            else {
                if(j==0) tmp[j]=(tmp[j]-87)*16;
                else tmp[j]-=87;
            }
        }
        mac[i]=tmp[0]+tmp[1];
        mac[i]=tmp[0]+tmp[1];
        temp++;
    }

}
