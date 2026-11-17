// SPDX-License-Identifier: Apache-2.0
// What an egress policy lets a guest reach, without opening a socket.
#include "policy.h"
#include <arpa/inet.h>
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
    if(failures)return 1;
    puts("policy egress: ok");return 0;
}
