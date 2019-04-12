//
// Created by Zeno on 2019/4/11.
//
#ifndef WINPCAPDEMO_GUI_H
#define WINPCAPDEMO_GUI_H
#include <string>
#include "winpCapDemo.h"

#endif //WINPCAPDEMO_GUI_H

using namespace std;

class PkgManager{
public:

private:
    PkgInfo * pkgs;

};

class Gui{
public:
    // Use message box to alert user
    bool sendMsg(string msg);
    // Send package info to gui
    bool sendPkg(PkgInfo pkgInfo);

private:
    PkgManager pkgManager;
};

