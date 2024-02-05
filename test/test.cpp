// test_vetcd.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinSock2.h>
#include "../src/zk_api.h"

int main()
{
    zk_init();

    void* cli = zk_connect("127.0.0.1:2181");
    if (cli == NULL)
    {
        printf("connect zk server failed\n");
        return 0;
    }
    printf("connect zk server ok!\n");

    // list data

    std::string sdata = zk_get_data(cli, "/", false);
    printf("stat /:\n%s\n", sdata.c_str());

    sdata = zk_get_value(cli, "/zookeeper/bb");
    printf("value /zookeeper/bb:\n%s\n", sdata.c_str());

    zk_close(cli);
    zk_release();
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
