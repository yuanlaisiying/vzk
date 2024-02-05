/**************************************************************************
zk_api.h

    a simple zookeeper client interface, for study only, not for production
    implement zk tcp protocol, no thirdparty request
    test zk3.6, zk3.8

    Copyright (c) ly
**************************************************************************/
#ifndef __VZK_H__
#define __VZK_H__

#define VZK_API

#include <string>

VZK_API bool zk_init();
VZK_API bool zk_release();

VZK_API void* zk_connect(const char* svr);
VZK_API void zk_close(void* ptr);
VZK_API bool zk_ping(void* ptr);

VZK_API std::string zk_get_value(void* ptr, const char* spath);

// return stat(;) + [ 0x02 + names ]...
VZK_API std::string zk_get_children2(void* ptr, const char* spath, bool bwatch);
// return stat(;) + 0x02 + data
VZK_API std::string zk_get_data(void* ptr, const char* spath, bool bwatch);
// return stat(;)
VZK_API std::string zk_set_data(void* ptr, const char* spath, const std::string& sdata, int ver = -1);
VZK_API bool zk_delete_path(void* ptr, const char* spath, int ver = -1);
// flags: 0-persistent, 1-ephemeral, 2-sequential, 3-ephemeral+sequential
// return created path name (maybe differ than spath in, i.e. sequential node name is changed)
VZK_API std::string zk_create_path(void* ptr, const char* spath, const std::string& sdata, int flags = 0);
VZK_API bool zk_exec_cmd(const char* svr, const char* scmd, std::string& sout);



#endif // __VZK_H__