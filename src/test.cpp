#include <iostream>
#include "winpCapDemo.h"
#include "pcap.h"
#include <winsock.h>
#include "winpCapCall.h"

using namespace std;

int main() {
    std::cout << "Hello, WinpCapDemo!" << std::endl;
    WinpCapDemo winpCapDemo;
    char source[PCAP_ERRBUF_SIZE+1];
    std::cout << "Input source:";
    fgets(source, PCAP_ERRBUF_SIZE, stdin);
    pcap_if_t* alldevs = winpCapDemo.getAdapters(source);

    printf("Enter the interface number:");
    int inum;
    scanf("%d", &inum);

    if(inum < 1 || inum > 3)
    {
        printf("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

//    if(!winpCapDemo.setFilter("ip")){
//        printf("!! Filter error!\n");
//    }

    /* 跳转到选中的适配器 */
    pcap_if_t* d;
    int i;
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    winpCapDemo.device = d;
    char mode[20];
    printf("Input system run mode(state for state mode):");
    scanf("%s", mode);

    if(NULL == (winpCapDemo.adhandle = winpCapDemo.chooseAdapter(d->name,mode))){
        pcap_freealldevs(alldevs);
    }


    pcap_freealldevs(alldevs);

    return 0;
}