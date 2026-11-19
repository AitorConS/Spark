// SPDX-License-Identifier: Apache-2.0
// Receiving from Unix sockets that may carry SCM_RIGHTS. XNU installs every
// descriptor a message carries in the receiver, even when the receiver passes
// no control buffer, or one too small for them: then it sets MSG_CTRUNC and
// leaves cmsg_len at the length the sender gave, past the buffer. A receiver
// must therefore read only what fits, close every descriptor it does not keep,
// and give each control buffer room for more descriptors than any sender may
// pass, so stray ones are seen and closed instead of left open beyond it.
#pragma once
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#define FD_RECV_MAX 16
#define FD_RECV_SPACE CMSG_SPACE(FD_RECV_MAX*sizeof(int))
// Every SCM_RIGHTS descriptor that fits in h's control data, bounded by
// msg_controllen and not by cmsg_len: the first is stored in *keep (closed
// when keep is NULL), all others are closed. Returns how many there were.
static inline unsigned fd_recv_collect(struct msghdr *h,int *keep){
    unsigned count=0;
    if(keep)*keep=-1;
    if(!h->msg_control)return 0;
    for(struct cmsghdr *c=CMSG_FIRSTHDR(h);c;c=CMSG_NXTHDR(h,c)){
        if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS||c->cmsg_len<CMSG_LEN(0))continue;
        size_t offset=(size_t)((unsigned char *)CMSG_DATA(c)-(unsigned char *)h->msg_control);
        if(offset>h->msg_controllen)break;
        size_t length=c->cmsg_len-CMSG_LEN(0),room=h->msg_controllen-offset;
        if(length>room)length=room;
        for(size_t i=0;i<length/sizeof(int);i++,count++){
            int fd;memcpy(&fd,CMSG_DATA(c)+i*sizeof(int),sizeof(fd));
            if(keep&&*keep<0)*keep=fd;else close(fd);
        }
    }
    return count;
}
// recvmsg() on a channel that never carries descriptors. Any it did carry are
// closed and *passed is set to 1 (MSG_CTRUNC counts: some could not be seen);
// otherwise *passed is 0. msg_flags, when not NULL, receives the message flags.
static inline ssize_t fd_recv_none(int fd,struct iovec *iov,int count,int flags,int *msg_flags,int *passed){
    char space[FD_RECV_SPACE];
    struct msghdr h={.msg_iov=iov,.msg_iovlen=count,.msg_control=space,.msg_controllen=sizeof(space)};
    ssize_t n=recvmsg(fd,&h,flags);
    *passed=n>=0&&(fd_recv_collect(&h,NULL)||(h.msg_flags&MSG_CTRUNC));
    if(msg_flags)*msg_flags=n>=0?h.msg_flags:0;
    return n;
}
// recv() with the same guarantee.
static inline ssize_t fd_recv_data(int fd,void *buffer,size_t size,int flags,int *passed){
    struct iovec io={buffer,size};
    return fd_recv_none(fd,&io,1,flags,NULL,passed);
}
