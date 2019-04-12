cmake_minimum_required(VERSION 3.9)
project(WinpCapDemo)

set(CMAKE_CXX_STANDARD 11)

INCLUDE_DIRECTORIES(C:/Users/Elvis/documents/WpdPack/include/)
LINK_DIRECTORIES(C:/Users/Elvis/documents/WpdPack/Lib/)
add_definitions(-D HAVE_REMOTE -D WPCAP)
link_libraries(wpcap.lib ws2_32.lib)

add_executable(WinpCapDemo src/winpCapDemo.cpp src/gui.h src/winpCapDemo.h src/gui.cpp src/winpCapCall.cpp src/winpCapCall.h src/test.cpp)