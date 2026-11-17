// SPDX-License-Identifier: Apache-2.0
// Exercise the vendored stack with the same mandatory socket-policy wrappers.
//
// An input is either one Ethernet frame at the default MTU (the original
// format, kept for the existing corpus) or, after the magic "HVFS", a
// big-endian MTU selector and a sequence of frames, each preceded by its
// big-endian 16-bit length. Several frames reach the stateful paths (IPv4
// reassembly, TCP) a single frame cannot, and the MTU selector the jumbo
// links. Every frame libslirp hands the guest must fit the link's MTU.
#include "net_backend.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static size_t link_mtu;
static ssize_t discard(const void *data,size_t size,void *opaque){
    (void)data;(void)opaque;
    if(size>link_mtu+14)abort(); // a frame larger than the guest's link
    return size;
}
static unsigned be16(const uint8_t *p){return (unsigned)p[0]<<8|p[1];}
int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){
    if(size>1<<20)return 0;
    static const struct hvf_security deny_all={0};
    struct hvf_options options={.security=&deny_all};
    int framed=size>=6&&!memcmp(data,"HVFS",4);
    if(framed){
        static const uint32_t mtus[]={1500,576,4000,9000};
        options.mtu=mtus[be16(data+4)%4];data+=6;size-=6;
    }
    link_mtu=options.mtu?options.mtu:1500;
    if(slirp_backend_open(&options,discard))return 0;
    if(!framed){if(size<=65536)slirp_backend_send(data,size);}
    else for(unsigned frames=0;size>=2&&frames<256;frames++){
        size_t n=be16(data);data+=2;size-=2;
        if(n>size)n=size;
        if(n)slirp_backend_send(data,n);
        data+=n;size-=n;
        slirp_backend_poll();
    }
    slirp_backend_poll();
    slirp_backend_close();return 0;
}
