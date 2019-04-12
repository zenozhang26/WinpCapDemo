#include <iostream>
#include "winpCapDemo.h"
#include "pcap.h"
#include <winsock.h>
#include "winpCapCall.h"

using namespace std;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

pcap_if_t* WinpCapDemo::getAdapters(string source) {
    printf("~~ Call getAdapters function.\n");

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    char source_char[PCAP_ERRBUF_SIZE+1];
    source.copy(source_char,PCAP_ERRBUF_SIZE,0);
    source_char[PCAP_ERRBUF_SIZE] = '\0';

    /* 获得接口列表 */
    if (pcap_findalldevs_ex(source_char, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
        exit(1);
    }

    for(pcap_if_t * d=alldevs;d;d=d->next)
    {
        ifprint(d);
    }
    //todo free alldevs after all calls
    return alldevs;
}

pcap_t* WinpCapDemo::chooseAdapter(char *adapterName,char *mode) {
    /* 打开设备 */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * adhandle;
    if ( (adhandle= pcap_open(adapterName,          // 设备名
                              65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // !!!混杂模式 PCAP_OPENFLAG_PROMISCUOUS
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
    ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", adapterName);
        /* 释放设备列表 */
        return NULL;
    }

    printf("\nlistening on %s...\n", adapterName);

    if(strcmp(mode, "state") == 0){
        /* 将接口设置为统计模式 */
        if (pcap_setmode(adhandle, MODE_STAT)<0)
        {
            fprintf(stderr,"\nError setting the mode.\n");
            return false;
        }
        printf("\nlistening mode: state");
        pcap_loop(adhandle, 0, dispatcher_handler, NULL);
        return adhandle;
    }


    /* 开始捕获 */
    pcap_loop(adhandle, 0, packet_handler, NULL);
    return adhandle;
}

bool WinpCapDemo::setFilter(string filterSentence) {
    //todo 存在bug需要修复
    pcap_if_t* d = this->device;
    u_int netmask;
    struct bpf_program fcode;
    pcap_t* adhandle = this->adhandle;

    if(pcap_datalink(adhandle) != DLT_IEEE802)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* 释放设备列表 */
        return false;
    }

    if(d->addresses != NULL)
        /* 获得接口第一个地址的掩码 */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
        //todo get netmask error.
    else
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask=0xffffff;

    //编译过滤器
    if (pcap_compile(adhandle, &fcode, filterSentence.c_str(), 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* 释放设备列表 */
        return false;
    }

    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* 释放设备列表 */
        return false;
    }
    return true;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
    //TODO finish self-defined packet handler
    packet_handler_winpCap(param, header, pkt_data);
}

//int main() {
//    std::cout << "Hello, WinpCapDemo!" << std::endl;
//    WinpCapDemo winpCapDemo;
//    return 0;
//}

WinpCapDemo::WinpCapDemo(){
    printf("~~ Init a WinpCapDemo.\n");
}

