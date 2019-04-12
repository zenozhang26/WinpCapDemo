//
// Created by Zeno on 2019/4/12.
//

#include <pcap.h>
#include "winpCapCall.h"

void ifprint(pcap_if_t *d)
{
    pcap_addr_t *a;
    char ip6str[128];

    /* 设备名(Name) */
    printf("%s\n",d->name);

    /* 设备描述(Description) */
    if (d->description)
        printf("\tDescription: %s\n",d->description);

    /* Loopback Address*/
    printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

    /* IP addresses */
    for(a=d->addresses;a;a=a->next) {
        printf("\tAddress Family: #%d\n",a->addr->sa_family);

        switch(a->addr->sa_family)
        {
            case AF_INET:
                printf("\tAddress Family Name: AF_INET\n");
                if (a->addr)
                    printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                if (a->netmask)
                    printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                if (a->broadaddr)
                    printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                if (a->dstaddr)
                    printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                break;

            case AF_INET6:
                printf("\tAddress Family Name: AF_INET6\n");
                if (a->addr)
                    printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
                break;

            default:
                printf("\tAddress Family Name: Unknown\n");
                break;
        }
    }
    printf("\n");
}

/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif


    if(getnameinfo(sockaddr,
                   sockaddrlen,
                   address,
                   addrlen,
                   NULL,
                   0,
                   NI_NUMERICHOST) != 0) address = NULL;

    return address;
}

/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
void packet_handler_winpCap(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
//    struct tm *ltime;
//    char timestr[16];
//    time_t local_tv_sec;
//
//    /* 将时间戳转换成可识别的格式 */
//    local_tv_sec = header->ts.tv_sec;
//    ltime=localtime(&local_tv_sec);
//    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
//
//    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* 打印数据包的时间戳和长度 */
    printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    /* 获得IP数据包头部的位置 */
    ih = (ip_header *) (pkt_data +
                        14); //以太网头部长度

    /* 获得UDP首部的位置 */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    /* 将网络字节序列转换成主机字节序列 */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    /* 打印IP地址和UDP端口 */
    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
           ih->saddr.byte1,
           ih->saddr.byte2,
           ih->saddr.byte3,
           ih->saddr.byte4,
           sport,
           ih->daddr.byte1,
           ih->daddr.byte2,
           ih->daddr.byte3,
           ih->daddr.byte4,
           dport);
}

void dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct timeval *old_ts = (struct timeval *)state;
    u_int delay;
    LARGE_INTEGER Bps,Pps;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 以毫秒计算上一次采样的延迟时间 */
    /* 这个值通过采样到的时间戳获得 */
    delay=(header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
    /* 获取每秒的比特数b/s */
    Bps.QuadPart=(((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
    /*                                            ^      ^
                                                  |      |
                                                  |      |
                                                  |      |
                              将字节转换成比特 --   |
                                                         |
                                       延时是以毫秒表示的 --
    */

    /* 得到每秒的数据包数量 */
    Pps.QuadPart=(((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));

    /* 将时间戳转化为可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* 打印时间戳*/
    printf("%s ", timestr);

    /* 打印采样结果 */
    printf("BPS=%I64u ", Bps.QuadPart);
    printf("PPS=%I64u\n", Pps.QuadPart);

    //存储当前的时间戳
    old_ts->tv_sec=header->ts.tv_sec;
    old_ts->tv_usec=header->ts.tv_usec;
}