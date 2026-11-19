// SPDX-License-Identifier: Apache-2.0
// What an egress policy lets a guest reach, without opening a socket.
#include "policy.h"
#include "seatbelt.h"
#include "socket_gate.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
static int failures;
static struct sockaddr_in at(const char *ip,unsigned port){
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port)};
    if(inet_pton(AF_INET,ip,&a.sin_addr)!=1){fprintf(stderr,"bad address %s\n",ip);exit(2);}
    return a;
}
static void expect(const char *what,int got,int want){
    if(got!=want){fprintf(stderr,"FAIL %s: got %d, want %d\n",what,got,want);failures++;}
}
static void reach(const char *ip,unsigned port,int want){
    struct sockaddr_in a=at(ip,port);char what[64];
    for(int type=SOCK_STREAM;type<=SOCK_DGRAM;type++){
        snprintf(what,sizeof(what),"%s %s:%u",type==SOCK_STREAM?"tcp":"udp",ip,port);
        expect(what,hvf_policy_allows(type,&a,0),want);
    }
}
// Stands in for the interface list: 93.184.216.34 is "this host".
static int pretend(const struct in_addr *a){return a->s_addr==htonl(0x5db8d822);}
int main(void){
    static const char *const public_addresses[]={"1.1.1.1","8.8.8.8","9.255.255.255","11.0.0.0","100.63.255.255","100.128.0.0",
        "126.255.255.255","128.0.0.0","169.253.255.255","169.255.0.0","172.15.255.255","172.32.0.0","192.167.255.255","192.169.0.0","223.255.255.255",
        "191.255.255.255","192.0.1.0","192.0.3.0","192.88.98.255","192.88.100.0","198.17.255.255","198.20.0.0",
        "198.51.99.255","198.51.101.0","203.0.112.255","203.0.114.0"};
    static const char *const closed_addresses[]={"0.0.0.1","10.0.0.1","10.255.255.255","100.64.0.1","100.127.255.255","127.0.0.1","127.255.255.254",
        "169.254.169.254","172.16.0.1","172.31.255.255","192.168.0.1","192.168.255.255","224.0.0.1","239.255.255.250","240.0.0.1","255.255.255.255",
        // Special-purpose blocks that are not globally reachable (RFC 6890).
        "192.0.0.1","192.0.0.170","192.0.0.255","192.0.2.1","192.88.99.1","198.18.0.1","198.19.255.255",
        "198.51.100.1","203.0.113.1"};
    // The default policy reaches nothing.
    hvf_policy_set(NULL);
    reach("1.1.1.1",443,0);reach("127.0.0.1",80,0);
    // public_egress reaches every public address and nothing nearer.
    struct hvf_security open={.public_egress=1};
    hvf_policy_set(&open);
    for(unsigned i=0;i<sizeof(public_addresses)/sizeof(*public_addresses);i++)reach(public_addresses[i],443,1);
    for(unsigned i=0;i<sizeof(closed_addresses)/sizeof(*closed_addresses);i++)reach(closed_addresses[i],443,0);
    reach("1.1.1.1",0,0);
    // It grants no listener, and an IPv6 or raw socket stays refused.
    struct sockaddr_in a=at("1.1.1.1",443);
    expect("listener",hvf_policy_allows(SOCK_STREAM,&a,1),0);
    expect("raw",hvf_policy_allows(SOCK_RAW,&a,0),0);
    a.sin_family=AF_INET6;expect("family",hvf_policy_allows(SOCK_STREAM,&a,0),0);
    // Exact rules and the resolver still open what public_egress does not.
    struct hvf_endpoint rule={.udp=0,.address={192,168,1,10},.port=5432};
    struct hvf_security mixed={.public_egress=1,.egress_count=1,.egress=&rule,.dns_address={192,168,1,1},.dns_port=53};
    hvf_policy_set(&mixed);
    a=at("192.168.1.10",5432);expect("exact rule",hvf_policy_allows(SOCK_STREAM,&a,0),1);
    expect("exact rule, other protocol",hvf_policy_allows(SOCK_DGRAM,&a,0),0);
    a=at("192.168.1.1",53);expect("resolver",hvf_policy_allows(SOCK_DGRAM,&a,0),1);
    reach("192.168.1.11",5432,0);reach("93.184.216.34",80,1);
    // The authority refuses, for public_egress only, what is this host's own
    // or on one of its links; exact rules still open such an address.
    hvf_policy_set_local(pretend);
    struct hvf_endpoint own={.udp=0,.address={93,184,216,34},.port=8443};
    struct hvf_security host={.public_egress=1,.egress_count=1,.egress=&own};
    hvf_policy_set(&host);
    reach("93.184.216.34",80,0);reach("1.1.1.1",443,1);
    a=at("93.184.216.34",8443);expect("exact rule to a local address",hvf_policy_allows(SOCK_STREAM,&a,0),1);
    hvf_policy_set_local(NULL);reach("93.184.216.34",80,1);
    // The real check: every IPv4 interface address and its subnet are local,
    // a public address off every link is not.
    struct in_addr in;
    inet_pton(AF_INET,"127.0.0.1",&in);expect("loopback is local",hvf_gate_host_local(&in),1);
    inet_pton(AF_INET,"1.1.1.1",&in);expect("1.1.1.1 is not local",hvf_gate_host_local(&in),0);
    struct ifaddrs *list;if(getifaddrs(&list)){perror("getifaddrs");return 1;}
    for(struct ifaddrs *i=list;i;i=i->ifa_next){
        if(!i->ifa_addr||i->ifa_addr->sa_family!=AF_INET)continue;
        struct in_addr own=((struct sockaddr_in *)(void *)i->ifa_addr)->sin_addr;char what[96];
        snprintf(what,sizeof(what),"%s address %s is local",i->ifa_name,inet_ntoa(own));expect(what,hvf_gate_host_local(&own),1);
        struct sockaddr_in mask={0};
        if(i->ifa_netmask)memcpy(&mask,i->ifa_netmask,i->ifa_netmask->sa_len<sizeof(mask)?i->ifa_netmask->sa_len:sizeof(mask));
        uint32_t m=ntohl(mask.sin_addr.s_addr);
        if(m>=0xff000000U&&m!=0xffffffffU){
            struct in_addr neighbour={htonl((ntohl(own.s_addr)&m)|(~m&(ntohl(own.s_addr)+1)))};
            snprintf(what,sizeof(what),"%s neighbour %s is local",i->ifa_name,inet_ntoa(neighbour));expect(what,hvf_gate_host_local(&neighbour),1);
        }
    }
    freeifaddrs(list);
    // ... and it works inside the authority's own Seatbelt profile.
    pid_t child=fork();
    if(!child){
        if(hvf_sandbox_install(HVF_GATE_PROFILE))_exit(2);
        inet_pton(AF_INET,"127.0.0.1",&in);int loopback=hvf_gate_host_local(&in);
        inet_pton(AF_INET,"1.1.1.1",&in);_exit(loopback==1&&hvf_gate_host_local(&in)==0?0:3);
    }
    int status;expect("interface list inside the authority profile",waitpid(child,&status,0)==child&&WIFEXITED(status)?WEXITSTATUS(status):-1,0);
    if(failures)return 1;
    puts("policy egress: ok");return 0;
}
