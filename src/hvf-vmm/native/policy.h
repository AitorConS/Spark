// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "hvf.h"
void hvf_policy_set(const struct hvf_security *);

#include <netinet/in.h>
int hvf_policy_allows(int,const struct sockaddr_in *,int);
int hvf_policy_public(const struct in_addr *);
// A further test for what public_egress grants: nonzero refuses the address
// as this host's own or on one of its links (the socket authority sets it).
void hvf_policy_set_local(int (*)(const struct in_addr *));
