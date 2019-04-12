//
// Created by Zeno on 2019/4/11.
//
#ifndef WINPCAPDEMO_WINPCAPDEMO_H
#define WINPCAPDEMO_WINPCAPDEMO_H
#include <string>
#include "pcap.h"
#endif //WINPCAPDEMO_WINPCAPDEMO_H

using namespace std;

class PkgInfo{

};

class WinpCapDemo{
public:
    WinpCapDemo();
    // Return adapter list from aimed source
    pcap_if_t * getAdapters(string source);
    // Choose aimed adapter
    pcap_t* chooseAdapter(char* adapterName,char* mode);
    // Compile and set package filter
    bool setFilter(string filterSentence);

    pcap_if_t* device;
    pcap_t * adhandle;
};


