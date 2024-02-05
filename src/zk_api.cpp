//#include "stdafx.h"
#include <string>
#include <iostream>
#include <vector>
#include <cstdlib>
#include <time.h>
#include <unordered_map>

#ifdef _MSC_VER
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mstcpip.h>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#define MSG_DONTWAIT 0
#else
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string>
#include <vector>
#include <map>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#define closesocket close
#define Sleep sleep
#endif

#include "zk_api.h"
#include <stdint.h>

using namespace std;

int64_t zk_ReverseBytes64(int64_t value)
{
    return (value & 0x00000000000000FF) << 56 | (value & 0x000000000000FF00) << 40 |
        (value & 0x0000000000FF0000) << 24 | (value & 0x00000000FF000000) << 8 |
        (value & 0x000000FF00000000) >> 8 | (value & 0x0000FF0000000000) >> 24 |
        (value & 0x00FF000000000000) >> 40 | (value & 0xFF00000000000000) >> 56;
}

int32_t zk_ReverseBytes32(int32_t value)
{
    return (value & 0x000000FF) << 24 | (value & 0x0000FF00) << 8 |
        (value & 0x00FF0000) >> 8 | (value & 0xFF000000) >> 24;
}

int16_t zk_ReverseBytes16(int16_t value)
{
    return (value & 0xFF) << 8 | (value & 0xFF00) >> 8;
}



/* predefined xid's values recognized as special by the server */
#define WATCHER_EVENT_XID -1 
#define PING_XID -2
#define AUTH_XID -4
#define SET_WATCHES_XID -8

/* zookeeper state constants */
#define EXPIRED_SESSION_STATE_DEF -112
#define AUTH_FAILED_STATE_DEF -113
#define CONNECTING_STATE_DEF 1
#define ASSOCIATING_STATE_DEF 2
#define CONNECTED_STATE_DEF 3
#define READONLY_STATE_DEF 5
#define SSL_CONNECTING_STATE_DEF 7
#define NOTCONNECTED_STATE_DEF 999

/* zookeeper event type constants */
#define CREATED_EVENT_DEF 1
#define DELETED_EVENT_DEF 2
#define CHANGED_EVENT_DEF 3
#define CHILD_EVENT_DEF 4
#define SESSION_EVENT_DEF -1
#define NOTWATCHING_EVENT_DEF -2


#define ZOO_NOTIFY_OP 0
#define ZOO_CREATE_OP 1
#define ZOO_DELETE_OP 2
#define ZOO_EXISTS_OP 3
#define ZOO_GETDATA_OP 4
#define ZOO_SETDATA_OP 5
#define ZOO_GETACL_OP 6
#define ZOO_SETACL_OP 7
#define ZOO_GETCHILDREN_OP 8
#define ZOO_SYNC_OP 9
#define ZOO_PING_OP 11
#define ZOO_GETCHILDREN2_OP 12
#define ZOO_CHECK_OP 13
#define ZOO_MULTI_OP 14
#define ZOO_CREATE2_OP 15
#define ZOO_RECONFIG_OP 16
#define ZOO_CHECK_WATCHES 17
#define ZOO_REMOVE_WATCHES 18
#define ZOO_CREATE_CONTAINER_OP 19
#define ZOO_DELETE_CONTAINER_OP 20
#define ZOO_CREATE_TTL_OP 21
#define ZOO_CLOSE_OP -11
#define ZOO_SETAUTH_OP 100
#define ZOO_SETWATCHES_OP 101

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4200)
#pragma pack(push, 1)
typedef __int64 int64;
typedef unsigned __int64 uint64;
#else
#pragma pack(1)
typedef long int64;
//typedef unsigned long uint64;
#endif

struct pkt_head
{
    int npkt_len;
};

struct pkt_connect: public pkt_head
{
    int32_t protocolVersion;
    int64_t lastZxidSeen;
    int32_t timeOut;
    int64_t sessionId;
    int32_t passwd_len;
    char passwd[16];
    char readOnly;
};

void conv_pkt_connect(pkt_connect& req)
{
    req.npkt_len = zk_ReverseBytes32(req.npkt_len);
    req.protocolVersion = zk_ReverseBytes32(req.protocolVersion);
    req.lastZxidSeen = zk_ReverseBytes64(req.lastZxidSeen);
    req.timeOut = zk_ReverseBytes32(req.timeOut);
    req.sessionId = zk_ReverseBytes64(req.sessionId);
    req.passwd_len = zk_ReverseBytes32(req.passwd_len);
};

struct pkt_connect_ans: public pkt_head
{
    int32_t protocolVersion;
    int32_t timeOut;
    int64_t sessionId;
    int32_t passwd_len;
    char passwd[16];
    char readOnly;
};
void conv_pkt_connect_ans(pkt_connect_ans& req)
{
    req.npkt_len = zk_ReverseBytes32(req.npkt_len);
    req.protocolVersion = zk_ReverseBytes32(req.protocolVersion);
    req.timeOut = zk_ReverseBytes32(req.timeOut);
    req.sessionId = zk_ReverseBytes64(req.sessionId);
    req.passwd_len = zk_ReverseBytes32(req.passwd_len);
};

struct pkt_reqhead : public pkt_head
{
    int xid;
    int ntype;
};
void conv_pkt_reqhead(pkt_reqhead& req)
{
    req.npkt_len = zk_ReverseBytes32(req.npkt_len);
    req.xid = zk_ReverseBytes32(req.xid);
    req.ntype = zk_ReverseBytes32(req.ntype);
};

struct pkt_anshead : public pkt_head
{
    int xid;
    int64_t zxid;
    int errcode;
};

void conv_pkt_anshead(pkt_anshead& req)
{
    req.npkt_len = zk_ReverseBytes32(req.npkt_len);
    req.xid = zk_ReverseBytes32(req.xid);
    req.zxid = zk_ReverseBytes64(req.zxid);
    req.errcode = zk_ReverseBytes32(req.errcode);
};

struct pkt_stat
{
    int64_t czxid;      // created zxid
    int64_t mzxid;      // last modified zxid
    int64_t ctime;      // created
    int64_t mtime;      // last modified
    int version;     // version
    int cversion;    // child version
    int aversion;    // acl version
    int64_t ephemeralOwner; // owner id if ephemeral, 0 otw
    int dataLength;  //length of the data in the node
    int numChildren; //number of children of this node
    int64_t pzxid;      // last modified children
};
void conv_pkt_stat(pkt_stat& req)
{
    req.czxid = zk_ReverseBytes64(req.czxid);
    req.mzxid = zk_ReverseBytes64(req.mzxid);
    req.ctime = zk_ReverseBytes64(req.ctime);
    req.mtime = zk_ReverseBytes64(req.mtime);
    req.ephemeralOwner = zk_ReverseBytes64(req.ephemeralOwner);
    req.pzxid = zk_ReverseBytes64(req.pzxid);
    req.version = zk_ReverseBytes32(req.version);
    req.cversion = zk_ReverseBytes32(req.cversion);
    req.aversion = zk_ReverseBytes32(req.aversion);
    req.dataLength = zk_ReverseBytes32(req.dataLength);
    req.numChildren = zk_ReverseBytes32(req.numChildren);
};
std::string get_pkt_stat_str(pkt_stat& req)
{
    std::string str;
    str += "czxid:";
    str += std::to_string(req.czxid);
    str += "\n";
    str += "mzxid:";
    str += std::to_string(req.mzxid);
    str += "\n";
    str += "ctime:";
    str += std::to_string(req.ctime);
    str += "\n";
    str += "mtime:";
    str += std::to_string(req.mtime);
    str += "\n";
    str += "version:";
    str += std::to_string(req.version);
    str += "\n";
    str += "cversion:";
    str += std::to_string(req.cversion);
    str += "\n";
    str += "aversion:";
    str += std::to_string(req.aversion);
    str += "\n";
    str += "ephemeralOwner:";
    str += std::to_string(req.ephemeralOwner);
    str += "\n";
    str += "dataLength:";
    str += std::to_string(req.dataLength);
    str += "\n";
    str += "numChildren:";
    str += std::to_string(req.numChildren);
    str += "\n";
    str += "pzxid:";
    str += std::to_string(req.pzxid);
    return str;
}

#define PKT_STAT_SIZE sizeof(pkt_stat)

#ifdef _MSC_VER
#pragma     pack(pop)
#pragma  warning(pop)
#else
#pragma     pack()
#endif


int vzk_send_sock(int sock, const char* buffer, uint32_t size)
{
    int index = 0, ret;
    while (size)
    {
        ret = (int)send(sock, &buffer[index], (int)size, 0);
        if (ret <= 0)
        {
            if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
                continue;
            printf("send failed, code: %d, error: %s\n", errno, strerror(errno));
            return (!ret) ? index : -1;
        }
        index += ret;
        size -= ret;
    }
    return index;
}

int set_non_block(int fd)
{
#ifdef _MSC_VER
    {
        u_long nonblocking = 1;
        if (ioctlsocket(fd, FIONBIO, &nonblocking) == SOCKET_ERROR) {
            return -1;
        }
    }
#else
    {
        int flags;
        if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
            return -1;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            return -1;
        }
    }
#endif
    return 0;
}
int set_block(int fd)
{
#ifdef _MSC_VER
    {
        u_long nonblocking = 0;
        if (ioctlsocket(fd, FIONBIO, &nonblocking) == SOCKET_ERROR) {
            return -1;
        }
    }
#else
    {
        int flags;
        if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
            return -1;
        }
        flags &= ~O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1) {
            return -1;
        }
    }
#endif
    return 0;
}

int connect_to_ip(const char* ip, int port, int ntimeout = -1)
{
    int sockfd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd <= 0)
    {
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((u_short)port);
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    if (ntimeout < 0)
        return !connect(sockfd, (const sockaddr*)& serv_addr, sizeof(serv_addr)) ? sockfd : -1;

    set_non_block(sockfd);
    int rc = connect(sockfd, (const sockaddr*)&serv_addr, sizeof(serv_addr));
    if (rc < 0)
    {
        //DWORD err = WSAGetLastError();
#ifdef _MSC_VER
        if (GetLastError() != WSAEWOULDBLOCK)
#else
        if (errno != EWOULDBLOCK)
#endif
        {
            closesocket(sockfd);
            return -1;
        }
    }

    fd_set rset, wset;
    struct timeval tval;
    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);
    wset = rset;
    tval.tv_sec = ntimeout;
    tval.tv_usec = 0;

    if ((rc = select(sockfd + 1, &rset, &wset, NULL, &tval)) == 0) {
        closesocket(sockfd); /* timeout */
        return -1;
    }

    set_block(sockfd);
    return sockfd;
}

class WsaInit
{
public:
    WsaInit() {
#ifdef _MSC_VER
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    }
    ~WsaInit() {
#ifdef _MSC_VER
        WSACleanup();
#endif
    }
};



struct socket_param
{
    int sock;
    int64_t send;
    int64_t recv;
    int ncpu;
};


typedef void(* cb_recv)(void* hConn, int state);

struct VZKObject
{
    int sock;
    int ans_count;
    bool async;
    long id;
    int readlen;
    char req[1024*1024];
    char ans[1024*1024];
    char* req_body;
    char* ans_body;
    pkt_head* pPktReq;
    pkt_head* pPktAns;
    cb_recv cb;
#ifdef _MSC_VER
    HANDLE tid;
#else
    pthread_t tid;
#endif
    bool bstop;
    long send_count_;
    long recv_count_;
    std::vector<char*> ans_bufs;
    std::string stoken;
    std::string splatform;

    pkt_connect zkauth;
    pkt_stat zkstat;

    VZKObject()
    {
        memset(&zkauth, 0, sizeof(zkauth));
        memset(&zkstat, 0, sizeof(zkstat));
        ans_count = 0;
        readlen = 0;
        bstop = false;
        sock = 0;

        async = false;
        id = 1;
        send_count_ = 0;
        recv_count_ = 0;
        memset(req, 0, 1024*1024);
        memset(ans, 0, 1024*1024);
        req_body = req + sizeof(pkt_head);
        ans_body = ans + sizeof(pkt_head);
        pPktReq = (pkt_head*)req;
        pPktAns = (pkt_head*)ans;
        cb = NULL;
        tid = 0;
    }
    
    ~VZKObject()
    {
#ifdef _MSC_VER
        if (tid != 0)
        {
            if (sock) closesocket(sock);
            sock = 0;
            WaitForSingleObject(tid, INFINITE);
            CloseHandle(tid);
            tid = 0;
    }
#else
        if (tid != 0)
        {
            if (sock) close(sock);
            sock = 0;
            pthread_join(tid, NULL);
            tid = 0;
        }
#endif
        
    }
    
    void ResetAnswer()
    {
        ans_count = 0;
        if (async == false) readlen = 0; // clear answer buffer
        for (auto& it: ans_bufs)
        {
            if (it == ans) continue;
            else delete[] it;
        }
        ans_bufs.clear();
    }
};

VZK_API bool zk_run(void* ptr, int nreadtimeout = 30);
VZK_API bool zk_send(void* ptr);
VZK_API bool zk_recv(void* ptr, int nreadtimeout = 30);

VZK_API bool zk_init()
{
#ifndef _MSC_VER
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
    {
        printf("failed to block SIGPIPE...\n");
    }
#else
    static WsaInit wsa;
#endif
    return true;
}

VZK_API bool zk_release()
{
    return true;
}

int vzk_recv_packet(VZKObject* obj, int ntimeout = 5)
{
    if (ntimeout > 0)
    {
        fd_set rset;
        struct timeval tval;
        FD_ZERO(&rset);
        FD_SET(obj->sock, &rset);
        tval.tv_sec = ntimeout;
        tval.tv_usec = 0;
        int rc = 0;
        if ((rc = select(obj->sock + 1, &rset, NULL, NULL, &tval)) == 0) {
            return 0;
        }
    }

    while (obj)
    {
        int avail = 1024*1024 - obj->readlen;
        int r = 0;
        {
            r = recv(obj->sock, &obj->ans[obj->readlen], avail, 0);
            if (r <= 0 || obj->bstop)
            {
                if (obj->bstop)
                    break;
                printf("recv failed, maybe connection drop...%d, code:%d, msg:%s\n", r, errno, strerror(errno));
                return -1;
            }
        }
        obj->readlen += r;
        int pktlen = zk_ReverseBytes32(obj->pPktAns->npkt_len) + sizeof(pkt_head);
        while (obj->readlen >= sizeof(pkt_head) && obj->readlen >= pktlen)
        {
            {
                char* buf2 = new char[pktlen];
                memcpy(buf2, obj->ans, pktlen);
                obj->ans_bufs.push_back(buf2);
                obj->ans_count++;

            }
            obj->readlen -= pktlen;
            memmove(obj->ans, &obj->ans[pktlen], obj->readlen);
            return 1;
        }
    }
    return -1;
}

#ifdef _MSC_VER
DWORD WINAPI thr_zk_recv(LPVOID param)
#else
void* thr_zk_recv(void* param)
#endif
{
    VZKObject* obj = (VZKObject *)param;
    if (obj == NULL)
    {
        printf("recv thread with null param exception!\n");
        return NULL;
    }

    int avail = 0;
    obj->readlen = 0;
    while (!obj->bstop)
    {
        avail = 1024*1024 - obj->readlen;
        int r = 0;
        {
            r = recv(obj->sock, &obj->ans[obj->readlen], avail, 0);
            if (r <= 0 || obj->bstop)
            {
                if (obj->bstop)
                    break;
                if (obj->cb)
                {
                    obj->cb(obj, -1);
                }
                printf("recv failed, maybe connection drop...%d, code:%d, msg:%s\n", r, errno, strerror(errno));
                return NULL;
            }
        }

        obj->readlen += r;
        int pktlen = zk_ReverseBytes32(obj->pPktAns->npkt_len) + sizeof(pkt_head);
        while (obj->readlen >= sizeof(pkt_head) && obj->readlen >= pktlen)
        {
            obj->ans_count = 1;
            obj->ans_bufs.push_back(obj->ans);
            if (obj->cb)
            {
                obj->cb(obj, 0);
            }
            obj->ResetAnswer();
            obj->readlen -= pktlen;
            if (obj->readlen) memmove(obj->ans, &obj->ans[pktlen], obj->readlen);
        }
    }
    return NULL;
}

VZK_API void* zk_connect(const char* svr)
{
    std::string sip = svr;
    int nport;
    int p1 = (int)sip.find(":");
    if (p1 < 0)
        return NULL;
    nport = atoi(sip.substr(p1 + 1, sip.length()).c_str());
    sip = sip.substr(0, p1);

    VZKObject* ptr = new VZKObject();
    ptr->async = false;

    ptr->sock = connect_to_ip(sip.c_str(), nport);
    if (ptr->sock <= 0)
    {
        printf("connect to svr failed, ip: %s@%d...\n", sip.c_str(), nport);
        delete ptr;
        return NULL;
    }

    {
        int sock = ptr->sock;
        int sndbuf = 2000 * 1000;
        int len = sizeof(int);
#ifdef _MSC_VER
        int ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, &len);
#else
        int ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, (socklen_t*)&len);
#endif
        //printf("get socket snd buf size:%i, ret: %d.\n", sndbuf, ret);

        sndbuf = 2000 * 1000;
        ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, sizeof(sndbuf));
        //printf("set socket snd buf size:%i, ret: %d.\n", sndbuf, ret);
#ifdef _MSC_VER
        ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, &len);
#else
        ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, (socklen_t*)&len);
#endif

         //printf("get socket snd buf size:%i, ret: %d.\n", sndbuf, ret);
        sndbuf = 2000 * 1000;
        ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&sndbuf, sizeof(sndbuf));
        //printf("set socket recv buf size:%i, ret: %d.\n", sndbuf, ret);
#ifdef _MSC_VER
        ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&sndbuf, &len);
#else
        ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&sndbuf, (socklen_t*)&len);
#endif

         //printf("get socket recv buf size:%i, ret: %d.\n", sndbuf, ret);
        (void)ret;
    }

    pkt_connect req;
    memset(&req, 0, sizeof(req));
    req.npkt_len = sizeof(pkt_connect) - 4;
    req.passwd_len = 16;
    req.timeOut = 60 * 1000;
    //req.lastZxidSeen = 943;
    //req.sessionId = 0x1000003cd6b000b;//  144172201458532798LL;
    int64_t* ppwd0 = (int64_t*)req.passwd;
    *ppwd0 = 1843633850855148061LL;
    *(ppwd0 + 1) = -5926082164580893310LL;
    char buf[128];
    sprintf(buf, "--send pkt len: %d\n", req.npkt_len);
    //OutputDebugStringA(buf);
    conv_pkt_connect(req);
    sprintf(buf, "--send pkt len: %d\n", req.npkt_len);
    //OutputDebugStringA(buf);
    vzk_send_sock(ptr->sock, (const char *)&req, sizeof(req));
    zk_recv(ptr);
    // 连接失败会被服务器关闭连接
    pkt_connect_ans* ans = (pkt_connect_ans*)ptr->ans;
    conv_pkt_connect_ans(*ans);
    //dump_packet((char *)ans, sizeof(pkt_connect_ans));
    if (ans->sessionId == 0)
    {
        zk_recv(ptr);
    }
    ptr->zkauth.sessionId = ans->sessionId;
    ptr->zkauth.readOnly = ans->readOnly;
    memcpy(ptr->zkauth.passwd, ans->passwd, sizeof(ans->passwd));
    ptr->zkauth.timeOut = ans->timeOut;
    ptr->zkauth.protocolVersion = ans->protocolVersion;
    ptr->zkauth.passwd_len = ans->passwd_len;
    int64_t* ppwd = (int64_t*)ans->passwd;


    if (ans->sessionId == 0)
    {
            delete ptr;
            ptr = NULL;
    }
    else
    {
        zk_ping(ptr);
        sprintf(buf, "session:%lld, p1:%lld, p2:%lld, zxid:%lld\n", ans->sessionId, *ppwd, *(ppwd + 1), ptr->zkauth.lastZxidSeen);
        //OutputDebugStringA(buf);
    }

    return ptr;
}

VZK_API void zk_close(void* ptr)
{
    VZKObject* obj = (VZKObject*)ptr;
    if (obj)
    {
        obj->bstop = true;
        if (obj->sock)
        {
            int sock = obj->sock;
            obj->sock = -1;

#ifdef _MSC_VER
            shutdown(sock, SD_BOTH);
            closesocket(sock);
#else
            shutdown(sock, 2);
            close(sock);
#endif
        }
        if (obj->tid != 0)
        {
            //printf("==> debug close sock: %d, tid: %li \n", obj->sock, obj->tid);
#ifdef _MSC_VER
            WaitForSingleObject(obj->tid, INFINITE);
            CloseHandle(obj->tid);
#else
            pthread_join(obj->tid, NULL);
#endif
            obj->tid = 0;
        }
        obj->sock = 0;
        obj->tid = 0;
        delete obj;
    }
}

VZK_API bool zk_run(void* ptr, int nreadtimeout/* = 30*/)
{
    VZKObject* obj = (VZKObject*)ptr;
    //obj->pPktReq->nxid = ++obj->id;
    obj->ResetAnswer();
    int s = vzk_send_sock(obj->sock, obj->req, obj->pPktReq->npkt_len);
    if (s <= 0)
    {
        printf("send failed...\n");
        return false;
    }

    if (obj->async == false)
    {
        return vzk_recv_packet(obj, nreadtimeout) > 0;
    }
    return true;
}
VZK_API bool zk_send(void* ptr)
{
    VZKObject* obj = (VZKObject*)ptr;
    //obj->pPktReq->nxid = ++obj->id;
    obj->ResetAnswer();
    int s = vzk_send_sock(obj->sock, obj->req, obj->pPktReq->npkt_len);
    if (s <= 0)
    {
        printf("send failed...\n");
        return false;
    }
    return true;
}
VZK_API bool zk_recv(void* ptr, int nreadtimeout/* = 30*/)
{
    VZKObject* obj = (VZKObject*)ptr;
    if (obj->async == false)
    {
        return vzk_recv_packet(obj, nreadtimeout) > 0;
    }
    else
    {
        printf("async mode unsupport recv..\n");
        return false;
    }
}
VZK_API bool zk_exec_cmd(const char* svr, const char* scmd, std::string& sout)
{
    sout.clear();
    std::string sip = svr;
    int nport;
    int p1 = (int)sip.find(":");
    if (p1 < 0)
    {
        sout = "error: ip address invaild";
        return false;
    }
    nport = atoi(sip.substr(p1 + 1, sip.length()).c_str());
    sip = sip.substr(0, p1);

    VZKObject* ptr = new VZKObject();
    ptr->sock = connect_to_ip(sip.c_str(), nport);
    if (ptr->sock <= 0)
    {
        delete ptr;
        sout = "error: connect failed";
        return false;
    }

    VZKObject* obj = ptr;
    strcpy(obj->req, scmd);
    if (vzk_send_sock(obj->sock, obj->req, 4) != 4)
    {
        delete ptr;
        sout = "error: send failed";
        return false;
    }
    obj->ans[0] = 0;
    int noffs = 0;
    int navail = 0;
    while (true)
    {
        navail = 1024 * 1024 - noffs;
        int rlen = recv(obj->sock, &obj->ans[noffs], navail, 0);
        if (rlen <= 0)
            break;
        noffs += rlen;
    }
    if (noffs > 0)
    {
        sout.assign(obj->ans, noffs);
    }
    delete ptr;
    return true;
}

VZK_API bool zk_ping(void* ptr)
{
    VZKObject* obj = (VZKObject*)ptr;
    pkt_reqhead pkt;
    pkt.ntype = ZOO_PING_OP;
    pkt.xid = obj->id++;
    pkt.npkt_len = sizeof(pkt_reqhead) - sizeof(pkt_head);
    conv_pkt_reqhead(pkt);
    int nlen = sizeof(pkt_reqhead);
    memcpy(obj->req, &pkt, nlen);
    vzk_send_sock(obj->sock, obj->req, nlen);
    memset(obj->ans, 0, sizeof(pkt_anshead));
    int nrc = vzk_recv_packet(obj, -1);
    pkt_anshead* pans = (pkt_anshead*)obj->ans;
    conv_pkt_anshead(*pans);
    if (pans->zxid > 0)
    {
        obj->zkauth.lastZxidSeen = pans->zxid;
    }
    //pans->errcode = zk_ReverseBytes32(pans->errcode);
    //pans->npkt_len = zk_ReverseBytes32(pans->npkt_len);
    if (nrc < 0 || pans->errcode != 0)
    {
        printf("---zk_ping server return error: %d \n", pans->errcode);
        return false;
    }
    return true;
}

VZK_API std::string zk_get_children2(void* ptr, const char* sname, bool bwatch)
{
    std::string rs;

    int slen = (int)strlen(sname);
    int nlen = 0;

    VZKObject* obj = (VZKObject*)ptr;
    pkt_reqhead pkt;
    pkt.ntype = ZOO_GETCHILDREN2_OP;
    pkt.xid = obj->id++;
    // reqhead + plen + path + bwatch
    pkt.npkt_len = sizeof(pkt_reqhead) + 4 + slen + 1 - sizeof(pkt_head);
    nlen = pkt.npkt_len + 4;
    conv_pkt_reqhead(pkt);
    char* pdata = obj->req;
    memcpy(pdata, &pkt, sizeof(pkt_reqhead));
    pdata += sizeof(pkt_reqhead);
    slen = zk_ReverseBytes32(slen);
    memcpy(pdata, &slen, 4);
    pdata += 4;
    memcpy(pdata, sname, strlen(sname));
    pdata += strlen(sname);
    *pdata = bwatch ? 1 : 0;
    vzk_send_sock(obj->sock, obj->req, nlen);
    obj->ans[0] = 0;
    int nrc = vzk_recv_packet(obj, -1);
    pkt_anshead* pans = (pkt_anshead*)obj->ans;
    conv_pkt_anshead(*pans);
    if (nrc < 0 || pans->errcode != 0)
    {
        printf("---getchildren2 server return error: %d \n", pans->errcode);
        return rs;
    }
    if (pans->zxid > 0)
    {
        obj->zkauth.lastZxidSeen = pans->zxid;
    }
    pdata = obj->ans + sizeof(pkt_anshead);
    int ncount = *(int*)(pdata);
    ncount = zk_ReverseBytes32(ncount);
    pdata += 4;
    for (int64_t i = 0; i < ncount; i ++)
    {
        int nlen = *(int*)(pdata);
        nlen = zk_ReverseBytes32(nlen);
        pdata += 4;
        if (rs.empty() == false) rs += 0x02;
        rs.append(pdata, nlen);
        pdata += nlen;
    }
    memcpy(&obj->zkstat, pdata, sizeof(pkt_stat));
    conv_pkt_stat(obj->zkstat);
    std::string strstat = get_pkt_stat_str(obj->zkstat);
    strstat += 0x02;
    strstat += rs;
    //if (rs.empty() == false)
    rs = strstat;
    return rs;
}

VZK_API std::string zk_get_value(void* ptr, const char* sname)
{
    bool bwatch = false;
    std::string rs;

    int slen = (int)strlen(sname);
    int nlen = 0;

    VZKObject* obj = (VZKObject*)ptr;
    pkt_reqhead pkt;
    pkt.ntype = ZOO_GETDATA_OP;
    pkt.xid = obj->id++;
    // reqhead + plen + path + bwatch
    pkt.npkt_len = sizeof(pkt_reqhead) + 4 + slen + 1 - sizeof(pkt_head);
    nlen = pkt.npkt_len + 4;
    conv_pkt_reqhead(pkt);
    char* pdata = obj->req;
    memcpy(pdata, &pkt, sizeof(pkt_reqhead));
    pdata += sizeof(pkt_reqhead);
    slen = zk_ReverseBytes32(slen);
    memcpy(pdata, &slen, 4);
    pdata += 4;
    memcpy(pdata, sname, strlen(sname));
    pdata += strlen(sname);
    *pdata = bwatch ? 1 : 0;
    vzk_send_sock(obj->sock, obj->req, nlen);
    obj->ans[0] = 0;
    int nrc = vzk_recv_packet(obj, -1);
    pkt_anshead* pans = (pkt_anshead*)obj->ans;
    if (nrc < 0 || pans->errcode != 0)
    {
        printf("---getdata server return error: %d \n", pans->errcode);
        return rs;
    }

    pdata = obj->ans + sizeof(pkt_anshead);
    {
        int nlen = *(int*)(pdata);
        nlen = zk_ReverseBytes32(nlen);
        if (nlen < 0)
            return rs;
        pdata += 4;
        if (rs.empty() == false) rs += 0x02;
        rs.append(pdata, nlen);
        pdata += nlen;
    }
    return rs;
}

VZK_API std::string zk_get_data(void* ptr, const char* sname, bool bwatch)
{
    std::string rs;

    int slen = (int)strlen(sname);
    int nlen = 0;

    VZKObject* obj = (VZKObject*)ptr;
    pkt_reqhead pkt;
    pkt.ntype = ZOO_GETDATA_OP;
    pkt.xid = obj->id++;
    // reqhead + plen + path + bwatch
    pkt.npkt_len = sizeof(pkt_reqhead) + 4 + slen + 1 - sizeof(pkt_head);
    nlen = pkt.npkt_len + 4;
    conv_pkt_reqhead(pkt);
    char* pdata = obj->req;
    memcpy(pdata, &pkt, sizeof(pkt_reqhead));
    pdata += sizeof(pkt_reqhead);
    slen = zk_ReverseBytes32(slen);
    memcpy(pdata, &slen, 4);
    pdata += 4;
    memcpy(pdata, sname, strlen(sname));
    pdata += strlen(sname);
    *pdata = bwatch ? 1 : 0;
    vzk_send_sock(obj->sock, obj->req, nlen);
    obj->ans[0] = 0;
    int nrc = vzk_recv_packet(obj, -1);
    pkt_anshead* pans = (pkt_anshead*)obj->ans;
    if (nrc < 0 || pans->errcode != 0)
    {
        printf("---getdata server return error: %d \n", pans->errcode);
        return rs;
    }

    pdata = obj->ans + sizeof(pkt_anshead);
    {
        int nlen = *(int*)(pdata);
        nlen = zk_ReverseBytes32(nlen);
        if (nlen < 0)
            return rs;
        pdata += 4;
        if (rs.empty() == false) rs += 0x02;
        rs.append(pdata, nlen);
        pdata += nlen;
    }
    memcpy(&obj->zkstat, pdata, sizeof(pkt_stat));
    conv_pkt_stat(obj->zkstat);
    std::string strstat = get_pkt_stat_str(obj->zkstat);
    strstat += 0x02;
    strstat += rs;
    //if (rs.empty() == false)
    rs = strstat;
    return rs;
}

VZK_API std::string zk_set_data(void* ptr, const char* spath, const std::string& sdata, int ver)
{
    std::string rs;

    int slen = (int)strlen(spath);
    int nlen = 0;

    VZKObject* obj = (VZKObject*)ptr;
    pkt_reqhead pkt;
    pkt.ntype = ZOO_SETDATA_OP;
    pkt.xid = obj->id++;
    // reqhead + plen + path + dlen + data + ver
    pkt.npkt_len = (int)(sizeof(pkt_reqhead) + 4 + slen + 4 + sdata.length() + 4 - sizeof(pkt_head));
    nlen = pkt.npkt_len + 4;
    conv_pkt_reqhead(pkt);
    char* pdata = obj->req;
    memcpy(pdata, &pkt, sizeof(pkt_reqhead));
    pdata += sizeof(pkt_reqhead);
    slen = zk_ReverseBytes32(slen);
    memcpy(pdata, &slen, 4);
    pdata += 4;
    memcpy(pdata, spath, strlen(spath));
    pdata += strlen(spath);
    slen = (int)sdata.length();
    slen = zk_ReverseBytes32(slen);
    memcpy(pdata, &slen, 4);
    pdata += 4;
    memcpy(pdata, sdata.c_str(), sdata.length());
    pdata += sdata.length();
    memcpy(pdata, &ver, 4);
    pdata += 4;

    vzk_send_sock(obj->sock, obj->req, (int)(pdata - obj->req));
    obj->ans[0] = 0;
    int nrc = vzk_recv_packet(obj, -1);
    pkt_anshead* pans = (pkt_anshead*)obj->ans;
    pans->errcode = zk_ReverseBytes32(pans->errcode);
    if (nrc < 0 || pans->errcode != 0)
    {
        printf("---getdata server return error: %d \n", pans->errcode);
        return "";
    }

    pdata = obj->ans + sizeof(pkt_anshead);
    memcpy(&obj->zkstat, pdata, sizeof(pkt_stat));
    conv_pkt_stat(obj->zkstat);
    std::string strstat = get_pkt_stat_str(obj->zkstat);
    //strstat += 0x02;
    //strstat += rs;
    //if (rs.empty() == false)
    //rs = strstat;
    return strstat;
}

VZK_API bool zk_delete_path(void* ptr, const char* spath, int ver/* = -1*/)
{
    std::string rs;

    int slen = (int)strlen(spath);
    int nlen = 0;

    VZKObject* obj = (VZKObject*)ptr;
    pkt_reqhead pkt;
    pkt.ntype = ZOO_DELETE_OP;
    pkt.xid = obj->id++;
    // reqhead + plen + path + ver
    pkt.npkt_len = sizeof(pkt_reqhead) + 4 + slen + 4 - sizeof(pkt_head);
    nlen = pkt.npkt_len + 4;
    conv_pkt_reqhead(pkt);
    char* pdata = obj->req;
    memcpy(pdata, &pkt, sizeof(pkt_reqhead));
    pdata += sizeof(pkt_reqhead);
    slen = zk_ReverseBytes32(slen);
    memcpy(pdata, &slen, 4);
    pdata += 4;
    memcpy(pdata, spath, strlen(spath));
    pdata += strlen(spath);
    memcpy(pdata, &ver, 4);
    pdata += 4;

    vzk_send_sock(obj->sock, obj->req, (int)(pdata - obj->req));
    obj->ans[0] = 0;
    int nrc = vzk_recv_packet(obj, -1);
    pkt_anshead* pans = (pkt_anshead*)obj->ans;
    pans->errcode = zk_ReverseBytes32(pans->errcode);
    pans->npkt_len = zk_ReverseBytes32(pans->npkt_len);
    if (nrc < 0 || pans->errcode != 0)
    {
        printf("---getdata server return error: %d \n", pans->errcode);
        return false;
    }

    pdata = obj->ans + sizeof(pkt_anshead);
    memcpy(&obj->zkstat, pdata, sizeof(pkt_stat));
    conv_pkt_stat(obj->zkstat);
    std::string strstat = get_pkt_stat_str(obj->zkstat);
    //strstat += 0x02;
    //strstat += rs;
    //if (rs.empty() == false)
    //rs = strstat;
    return true;
}

VZK_API std::string zk_create_path(void* ptr, const char* spath, const std::string& sdata, int flags)
{
    std::string rs;

    int slen = (int)strlen(spath);
    int nlen = 0;

    VZKObject* obj = (VZKObject*)ptr;
    pkt_reqhead pkt;
    pkt.ntype = ZOO_CREATE_OP;
    pkt.xid = obj->id++;
    // reqhead + plen + path + dlen + data + ACL(perms+world+anyone) + flags4
    pkt.npkt_len = (int)(sizeof(pkt_reqhead) + 4 + slen + 4 + sdata.length() + (4 + 4 + 4 + 5 + 4 + 6) + 4 - sizeof(pkt_head));
    nlen = pkt.npkt_len + 4;
    conv_pkt_reqhead(pkt);
    char* pdata = obj->req;
    memcpy(pdata, &pkt, sizeof(pkt_reqhead));
    pdata += sizeof(pkt_reqhead);

    slen = zk_ReverseBytes32(slen);
    memcpy(pdata, &slen, 4);
    pdata += 4;
    memcpy(pdata, spath, strlen(spath));
    pdata += strlen(spath);

    slen = (int)sdata.length();
    slen = zk_ReverseBytes32(slen);
    memcpy(pdata, &slen, 4);
    pdata += 4;
    memcpy(pdata, sdata.c_str(), sdata.length());
    pdata += sdata.length();

    int ncount = zk_ReverseBytes32(1);
    memcpy(pdata, &ncount, 4);
    pdata += 4;

    int perms = 0x1f;
    perms = zk_ReverseBytes32(perms);
    memcpy(pdata, &perms, 4);
    pdata += 4;

    slen = zk_ReverseBytes32(5);
    memcpy(pdata, &slen, 4);
    pdata += 4;

    memcpy(pdata, "world", 5);
    pdata += 5;

    slen = zk_ReverseBytes32(6);
    memcpy(pdata, &slen, 4);
    pdata += 4;

    memcpy(pdata, "anyone", 6);
    pdata += 6;

    flags = zk_ReverseBytes32(flags);
    memcpy(pdata, &flags, 4);
    pdata += 4;

    slen = (int)(pdata - obj->req);
    pkt_reqhead* preq = (pkt_reqhead*)obj->req;
    preq->npkt_len = zk_ReverseBytes32(slen - 4);
    vzk_send_sock(obj->sock, obj->req, (int)(pdata - obj->req));
    memset(obj->ans, 0, sizeof(pkt_anshead));
    int nrc = vzk_recv_packet(obj, -1);
    pkt_anshead* pans = (pkt_anshead*)obj->ans;
    pans->errcode = zk_ReverseBytes32(pans->errcode);
    pans->npkt_len = zk_ReverseBytes32(pans->npkt_len);
    if (nrc < 0 || pans->errcode != 0)
    {
        printf("---getdata server return error: %d \n", pans->errcode);
        return "";
    }

    pdata = obj->ans + sizeof(pkt_anshead);
    {
        int nlen = *(int*)(pdata);
        nlen = zk_ReverseBytes32(nlen);
        pdata += 4;
        rs.append(pdata, nlen);
        pdata += nlen;
    }
    return rs;

}