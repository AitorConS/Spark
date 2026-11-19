// SPDX-License-Identifier: Apache-2.0
// Wire format of the direct-link channel between the broker and the VMM (see
// net_backend_ipc.c): 16-byte datagrams, magic "HVLK", kind, LE generation,
// and at most one SCM_RIGHTS descriptor (the connected switch socket).
#pragma once
#include "fd_recv.h"
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#define LINK_MESSAGE 16
enum {LINK_OFFER='S',LINK_ACK='A',LINK_LOST='R'};
static int link_message(int fd,uint8_t kind,uint64_t generation,int descriptor){
    uint8_t wire[LINK_MESSAGE]={'H','V','L','K',kind};
    for(unsigned i=0;i<8;i++)wire[8+i]=(uint8_t)(generation>>(8*i));
    char space[CMSG_SPACE(sizeof(int))];
    struct iovec io={wire,sizeof(wire)};
    struct msghdr h={.msg_iov=&io,.msg_iovlen=1};
    if(descriptor>=0){
        memset(space,0,sizeof(space));h.msg_control=space;h.msg_controllen=sizeof(space);
        struct cmsghdr *c=CMSG_FIRSTHDR(&h);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c),&descriptor,sizeof(descriptor));
    }
    return sendmsg(fd,&h,MSG_DONTWAIT)==(ssize_t)sizeof(wire)?0:-1;
}
// Returns 1 with a message (and *descriptor, or -1), 0 when none is queued,
// -1 when the channel passed more than one descriptor with a message, or more
// than fit (MSG_CTRUNC): every one seen is closed and the channel is unusable.
static int link_receive(int fd,uint8_t *kind,uint64_t *generation,int *descriptor){
    // Bounded: a flood of invalid datagrams must not keep the device loop here.
    for(unsigned budget=0;budget<64;budget++){
        uint8_t wire[LINK_MESSAGE+1];char space[FD_RECV_SPACE];
        struct iovec io={wire,sizeof(wire)};
        struct msghdr h={.msg_iov=&io,.msg_iovlen=1,.msg_control=space,.msg_controllen=sizeof(space)};
        ssize_t n=recvmsg(fd,&h,MSG_DONTWAIT);
        if(n<0)return 0;
        if(fd_recv_collect(&h,descriptor)>1||(h.msg_flags&MSG_CTRUNC)){
            if(*descriptor>=0)close(*descriptor);
            *descriptor=-1;return -1;
        }
        if(n!=LINK_MESSAGE||memcmp(wire,"HVLK",4)){if(*descriptor>=0)close(*descriptor);continue;}
        *kind=wire[4];*generation=0;
        for(unsigned i=0;i<8;i++)*generation|=(uint64_t)wire[8+i]<<(8*i);
        return 1;
    }
    return 0;
}
