/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <error.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <assert.h>

#include <compat.h> /* hexdump */

#include "app_common.h"
#include "xfrm_events.h"
#include "pfkey_utils.h"

#define DPA_IPSEC_ADDR_T_IPv4 4
#define DPA_IPSEC_ADDR_T_IPv6 6

#define NLA_DATA(na) ((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_NEXT(na, len)	((len) -= NLA_ALIGN((na)->nla_len), \
				(struct nlattr *)((char *)(na) \
				+ NLA_ALIGN((na)->nla_len)))
#define NLA_OK(na, len) ((len) >= (int)sizeof(struct nlattr) && \
			   (na)->nla_len >= sizeof(struct nlattr) && \
			   (na)->nla_len <= (len))

struct thread_data {
	int dpa_ipsec_id;
};

/* SADB */
LIST_HEAD(nf_sa_list);
/* pending SP list */
static LIST_HEAD(pending_sp);

static struct thread_data *xfrm_data;
static volatile sig_atomic_t quit;
static pthread_t tid;
static unsigned next_in_ipsec_policy_id;
static unsigned next_out_ipsec_policy_id;

static void xfrm_sig_handler(int signum)
{
	TRACE("xfrm signal handler catched signal %d\n", signum);
	if (signum == SIGUSR2)
		quit = 1;
}

static int create_nl_socket(int protocol, int groups)
{
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = groups;
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		goto err;

	return fd;
err:
	close(fd);
	return -1;
}

static int offload_sa(int dpa_ipsec_id, struct nf_sa *nf_sa, struct nf_pol *nf_pol)
{
	struct nf_ipsec_sa *sa_params = &nf_sa->sa_params;
	struct xfrm_usersa_info *sa_info = &nf_sa->xfrm_sa_info;
	struct xfrm_encap_tmpl *encap = &nf_sa->encap;
	struct xfrm_selector *sel = &nf_pol->xfrm_pol_info.sel;
	struct nf_ipsec_sa_selector sa_sel;
	struct nf_ipsec_sa_add_inargs sa_in;
	struct nf_ipsec_sa_add_outargs sa_out;
	int dir = nf_pol->xfrm_pol_info.dir;
	int ret = 0;

	if (!sa_params->crypto_params.cipher_key ||
		!sa_params->crypto_params.auth_key)
		return -1;
	hexdump(sa_params->crypto_params.cipher_key,
		sa_params->crypto_params.cipher_key_len_bits);

	hexdump(sa_params->crypto_params.auth_key,
		sa_params->crypto_params.auth_key_len_bits);

	memset(&sa_in, 0, sizeof(struct nf_ipsec_sa_add_inargs));
	sa_in.sa_params = sa_params;

	if (dir == XFRM_POLICY_OUT)
		sa_in.dir = NF_IPSEC_OUTBOUND;
	else if (dir == XFRM_POLICY_IN)
		sa_in.dir = NF_IPSEC_INBOUND;
	else
		return -EBADMSG;

	sa_params->spi = sa_info->id.spi;
	sa_params->protocol = IPPROTO_ESP;

	memset(&sa_sel, 0, sizeof(sa_sel));

	if (dir == XFRM_POLICY_OUT) {
		if (sa_info->family == AF_INET) {
			sa_params->te_addr.src_ip.version = NF_IPV4;
			sa_params->te_addr.src_ip.ipv4 = sa_info->saddr.a4;
			sa_params->te_addr.dest_ip.version = NF_IPV4;
			sa_params->te_addr.dest_ip.ipv4 = sa_info->id.daddr.a4;
			sa_params->outb.dscp = app_conf.outer_tos;

			if (encap->encap_sport && encap->encap_dport)
				sa_params->cmn_flags |=
				   NF_IPSEC_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL;

			if (app_conf.ob_ecn) {
				TRACE("Outbound ECN tunneling set\n");
				sa_params->outb.dscp_handle = NF_IPSEC_DSCP_COPY;
			}
		} else if (sa_info->family == AF_INET6) {
			memcpy(sa_params->te_addr.src_ip.ipv6.b_addr,
			       sa_info->saddr.a6, sizeof(sa_info->saddr.a6));
			memcpy(sa_params->te_addr.dest_ip.ipv6.b_addr,
			       sa_info->id.daddr.a6,
			       sizeof(sa_info->id.daddr.a6));
			sa_params->outb.dscp = (uint8_t)(0x6<<28);
		}

		if (encap->encap_sport && encap->encap_dport) {
			sa_params->nat_info.src_port = encap->encap_sport;
			sa_params->nat_info.dest_port = encap->encap_dport;
		}
		sa_params->outb.iv = NULL;
		sa_sel.policy_id = next_out_ipsec_policy_id++;
	} else if (dir == XFRM_POLICY_IN) {
		if (encap->encap_sport && encap->encap_dport) {
			sa_params->cmn_flags |=
			   NF_IPSEC_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL;

			sa_params->nat_info.src_port = encap->encap_sport;
			sa_params->nat_info.dest_port = encap->encap_dport;
		}
		if (sa_info->family == AF_INET) {
			sa_params->te_addr.src_ip.version = NF_IPV4;
			sa_params->te_addr.src_ip.ipv4 = sa_info->saddr.a4;
			sa_params->te_addr.dest_ip.version = NF_IPV4;
			sa_params->te_addr.dest_ip.ipv4 = sa_info->id.daddr.a4;

			if (app_conf.ib_ecn) {
				TRACE("Inbound ECN tunneling set\n");
				sa_params->inb.flags =
						NF_IPSEC_INB_SA_PROPOGATE_ECN;
			}
		} else if (sa_info->family == AF_INET6) {
			memcpy(sa_params->te_addr.src_ip.ipv6.b_addr,
			       sa_info->saddr.a6, sizeof(sa_info->saddr.a6));
			memcpy(sa_params->te_addr.dest_ip.ipv6.b_addr,
			       sa_info->id.daddr.a6,
			       sizeof(sa_info->id.daddr.a6));
		}

		sa_sel.policy_id = next_in_ipsec_policy_id++;
	}

	/* For now, we support only one selector */
	sa_params->n_selectors = 1;
	sa_params->selectors = &sa_sel;

	if (sel->family == AF_INET) {
		sa_sel.selector.version = NF_IPV4;
		sa_sel.selector.src_ip4.type = NF_IPA_SUBNET;
		sa_sel.selector.src_ip4.subnet.addr = sel->saddr.a4;
		sa_sel.selector.src_ip4.subnet.prefix_len = sel->prefixlen_s;
		sa_sel.selector.dest_ip4.type = NF_IPA_SUBNET;
		sa_sel.selector.dest_ip4.subnet.addr = sel->daddr.a4;
		sa_sel.selector.dest_ip4.subnet.prefix_len = sel->prefixlen_d;
	} else {
		sa_sel.selector.version = NF_IPV6;
		sa_sel.selector.src_ip6.type = NF_IPA_SUBNET;
		sa_sel.selector.dest_ip6.type = NF_IPA_SUBNET;
		memcpy(sa_sel.selector.src_ip6.subnet.addr.b_addr,
			sel->saddr.a6, sizeof(sel->saddr.a6));
		memcpy(sa_sel.selector.dest_ip6.subnet.addr.b_addr,
			sel->daddr.a6, sizeof(sel->daddr.a6));
		sa_sel.selector.src_ip6.subnet.prefix_len = sel->prefixlen_s;
		sa_sel.selector.dest_ip6.subnet.prefix_len = sel->prefixlen_d;
	}

	sa_sel.selector.protocol = sel->proto;
	if (sel->proto == IPPROTO_UDP || sel->proto == IPPROTO_TCP) {
		sa_sel.selector.src_port.type = NF_L4_PORT_SINGLE;
		sa_sel.selector.src_port.single.port = sel->sport;
		sa_sel.selector.dest_port.type = NF_L4_PORT_SINGLE;
		sa_sel.selector.dest_port.single.port = sel->dport;
	} else if (sel->proto == IPPROTO_ICMP) {
		/* we do not handle icmp code/type */
		memset(&sa_sel.selector.src_port,
			0, sizeof(sa_sel.selector.src_port));
		memset(&sa_sel.selector.dest_port,
			0, sizeof(sa_sel.selector.dest_port));
	}

	/* Store information needed to perform remove */
	nf_sa->dir = sa_in.dir;
	nf_sa->spi = sa_in.sa_params->spi;
	nf_sa->protocol = sa_in.sa_params->protocol;
	if (sa_info->family == AF_INET)
		nf_sa->dest_ip = sa_params->te_addr.dest_ip;
	else
		memcpy(&nf_sa->dest_ip,
			&sa_params->te_addr.dest_ip, sizeof(nf_sa->dest_ip));

	ret = nf_ipsec_sa_add(dpa_ipsec_id, &sa_in, 0, &sa_out, NULL);
	return ret;
}

static inline int offload_policy(struct nf_ipsec_policy *pol_params,
			struct xfrm_selector *sel, enum nf_ipsec_direction dir)
{
	struct nf_ipsec_spd_add_inargs spd_add_in;
	struct nf_ipsec_spd_add_outargs	spd_add_out;
	struct nf_ipsec_selector spd_sel;
	int ret = 0;

	memset(&spd_add_in, 0, sizeof(spd_add_in));

	spd_add_in.tunnel_id = 0;
	spd_add_in.dir = dir;
	spd_add_in.spd_params.policy_id = pol_params->policy_id;

	spd_add_in.spd_params.action = NF_IPSEC_POLICY_ACTION_IPSEC;
	spd_add_in.spd_params.status = NF_IPSEC_POLICY_STATUS_ENABLE;
	spd_add_in.spd_params.position = NF_IPSEC_POLICY_POSITION_BEGIN;
	spd_add_in.spd_params.relative_policy_id = 0;
	spd_add_in.spd_params.n_dscp_ranges = 0;
	spd_add_in.spd_params.dscp_ranges = NULL;
	spd_add_in.spd_params.redside = NF_IPSEC_POLICY_REDSIDE_FRAGMENTATION_DISABLE;

	memset(&spd_sel, 0, sizeof(spd_sel));

	spd_add_in.spd_params.n_selectors = 1;
	spd_add_in.spd_params.selectors = &spd_sel;

	if (sel->family == AF_INET) {
		spd_sel.version = NF_IPV4;
		spd_sel.src_ip4.type = NF_IPA_SUBNET;
		spd_sel.src_ip4.subnet.addr = sel->saddr.a4;
		spd_sel.src_ip4.subnet.prefix_len = sel->prefixlen_s;
		spd_sel.dest_ip4.type = NF_IPA_SUBNET;
		spd_sel.dest_ip4.subnet.addr = sel->daddr.a4;
		spd_sel.dest_ip4.subnet.prefix_len = sel->prefixlen_d;
	} else if (sel->family == AF_INET6) {
		spd_sel.version = NF_IPV6;
		spd_sel.src_ip6.type = NF_IPA_SUBNET;
		spd_sel.dest_ip6.type = NF_IPA_SUBNET;
		memcpy(spd_sel.src_ip6.subnet.addr.b_addr,
			sel->saddr.a6, sizeof(sel->saddr.a6));
		memcpy(spd_sel.dest_ip6.subnet.addr.b_addr,
			sel->daddr.a6, sizeof(sel->daddr.a6));
		spd_sel.src_ip6.subnet.prefix_len = sel->prefixlen_s;
		spd_sel.dest_ip6.subnet.prefix_len = sel->prefixlen_d;
	}
	spd_sel.protocol = sel->proto;

	if (sel->proto == IPPROTO_UDP || sel->proto == IPPROTO_TCP) {
		spd_sel.src_port.type = NF_L4_PORT_SINGLE;
		spd_sel.src_port.single.port = sel->sport;
		spd_sel.dest_port.type = NF_L4_PORT_SINGLE;
		spd_sel.dest_port.single.port = sel->dport;
	} else if (sel->proto == IPPROTO_ICMP) {
		/* we do not handle icmp code/type */
		memset(&spd_sel.src_port, 0, sizeof(spd_sel.src_port));
		memset(&spd_sel.dest_port, 0, sizeof(spd_sel.dest_port));
	}

	ret = nf_ipsec_spd_add(0, &spd_add_in, 0, &spd_add_out, 0);
	return ret;
}

void dump_xfrm_sa_info(struct xfrm_usersa_info *sa_info)
{
	struct in_addr saddr_in;
	struct in_addr daddr_in;
	struct in6_addr saddr_in6;
	struct in6_addr daddr_in6;
	__maybe_unused void *saddr, *daddr;
	char dst[INET6_ADDRSTRLEN];

	memset(dst, 0, sizeof(dst));
	if (sa_info->family == AF_INET) {
		saddr_in.s_addr = sa_info->saddr.a4;
		daddr_in.s_addr = sa_info->id.daddr.a4;
		saddr = &saddr_in.s_addr;
		daddr = &daddr_in.s_addr;
	} else if (sa_info->family == AF_INET6) {
		memcpy(&saddr_in6.s6_addr,
			&sa_info->saddr.a6,
			sizeof(saddr_in6.s6_addr));
		memcpy(&daddr_in6.s6_addr,
			&sa_info->id.daddr.a6,
			sizeof(daddr_in6.s6_addr));
		saddr = &saddr_in6.s6_addr;
		daddr = &daddr_in6.s6_addr;
	} else {
		error(0, EINVAL, "family is not IPv4 or IPv6");
		return;
	}

	printf("\tspi 0x%x\n", sa_info->id.spi);
	printf("\tsaddr %s\n", inet_ntop(sa_info->family,
				saddr, dst, sizeof(dst)));
	printf("\tdaddr %s\n", inet_ntop(sa_info->family,
				daddr, dst, sizeof(dst)));
}

void trace_xfrm_policy_info(struct xfrm_userpolicy_info *pol_info)
{
	__maybe_unused const char *dir;
	struct in_addr saddr_in;
	struct in_addr daddr_in;
	struct in6_addr saddr_in6;
	struct in6_addr daddr_in6;
	__maybe_unused void *saddr, *daddr;
	char dst[INET6_ADDRSTRLEN];

	memset(dst, 0, sizeof(dst));
	if (pol_info->sel.family == AF_INET) {
		saddr_in.s_addr = pol_info->sel.saddr.a4;
		daddr_in.s_addr = pol_info->sel.daddr.a4;
		saddr = &saddr_in.s_addr;
		daddr = &daddr_in.s_addr;
	} else if (pol_info->sel.family == AF_INET6) {
		memcpy(&saddr_in6.s6_addr,
			&pol_info->sel.saddr.a6,
			sizeof(saddr_in6.s6_addr));
		memcpy(&daddr_in6.s6_addr,
			&pol_info->sel.daddr.a6,
			sizeof(daddr_in6.s6_addr));
		saddr = &saddr_in6.s6_addr;
		daddr = &daddr_in6.s6_addr;
	} else
		return;


	dir = (pol_info->dir == XFRM_POLICY_OUT) ? "OUT" :
		((pol_info->dir == XFRM_POLICY_IN) ? "IN" : "FWD");

	TRACE("xfrm pol index %d dir %s\n",
		pol_info->index, dir);
	TRACE("\tsel saddr %s", inet_ntop(pol_info->sel.family,
				saddr, dst, sizeof(dst)));
	TRACE(" daddr %s\n", inet_ntop(pol_info->sel.family,
				daddr, dst, sizeof(dst)));
}

static void trace_nf_policy(struct nf_pol *nf_pol)
{
	struct in_addr saddr_in;
	struct in_addr daddr_in;
	struct in6_addr saddr_in6;
	struct in6_addr daddr_in6;
	__maybe_unused void *saddr, *daddr;
	char dst[INET6_ADDRSTRLEN];

	memset(dst, 0, sizeof(dst));

	if (nf_pol->sa_family == AF_INET) {
		saddr_in.s_addr = nf_pol->sa_saddr.a4;
		daddr_in.s_addr = nf_pol->sa_daddr.a4;
		saddr = &saddr_in.s_addr;
		daddr = &daddr_in.s_addr;
	} else if (nf_pol->sa_family == AF_INET6) {
		memcpy(&saddr_in6.s6_addr,
			&nf_pol->sa_saddr.a6,
			sizeof(saddr_in6.s6_addr));
		memcpy(&daddr_in6.s6_addr,
			&nf_pol->sa_daddr.a6,
			sizeof(daddr_in6.s6_addr));
		saddr = &saddr_in6.s6_addr;
		daddr = &daddr_in6.s6_addr;
	} else
		return;

	trace_xfrm_policy_info(&nf_pol->xfrm_pol_info);
	TRACE("\ttmpl saddr %s", inet_ntop(nf_pol->sa_family,
				saddr, dst, sizeof(dst)));
	TRACE(" daddr %s\n", inet_ntop(nf_pol->sa_family,
				daddr, dst, sizeof(dst)));
}

static inline int do_offload(int dpa_ipsec_id, struct nf_sa *nf_sa,
			struct nf_pol *nf_pol)
{
	int ret = 0;
	if (nf_sa->sa_init[nf_pol->xfrm_pol_info.dir] == false) {
		ret = offload_sa(dpa_ipsec_id, nf_sa, nf_pol);
		if (ret < 0) {
			fprintf(stderr, "offload_sa failed , ret %d\n", ret);
			free(nf_sa->sa_params.crypto_params.cipher_key);
			free(nf_sa->sa_params.crypto_params.auth_key);
			list_del(&nf_sa->list);
			free(nf_sa);
			return ret;
		}
		nf_sa->sa_init[nf_pol->xfrm_pol_info.dir] = true;
		TRACE("%s SA: \n", (nf_pol->xfrm_pol_info.dir ==
			XFRM_POLICY_OUT) ? "OUT" : "IN ");
#ifdef ENABLE_TRACE
		dump_xfrm_sa_info(&nf_sa->xfrm_sa_info);
#endif
	}

	if (nf_pol->xfrm_pol_info.dir == XFRM_POLICY_IN) {
		nf_pol->dir = NF_IPSEC_INBOUND;
		return ret;
	} else
		nf_pol->dir = NF_IPSEC_OUTBOUND;

	nf_pol->pol_params.policy_id = next_out_ipsec_policy_id++;

	ret = offload_policy(&nf_pol->pol_params,
			&nf_pol->xfrm_pol_info.sel, nf_pol->dir);
	if (ret < 0) {
		fprintf(stderr, "offload_policy failed, ret %d\n", ret);
		list_del(&nf_pol->list);
		free(nf_pol);
		return ret;
	}
	nf_pol->policy_id = nf_pol->pol_params.policy_id;
	trace_nf_policy(nf_pol);
	return ret;
}

static inline struct nf_sa
*find_nf_sa(struct xfrm_usersa_id *usersa_id)
{
	struct list_head *l, *tmp;
	struct nf_sa *nf_sa = NULL;
	list_for_each_safe(l, tmp, &nf_sa_list) {
		nf_sa = (struct nf_sa *)l;
		if (nf_sa->xfrm_sa_info.family == AF_INET &&
			nf_sa->xfrm_sa_info.id.spi ==
			usersa_id->spi &&
			nf_sa->xfrm_sa_info.id.daddr.a4 ==
			usersa_id->daddr.a4) {
			return nf_sa;
		} else if (nf_sa->xfrm_sa_info.family == AF_INET6 &&
			nf_sa->xfrm_sa_info.id.spi ==
			usersa_id->spi &&
			!memcmp(&nf_sa->xfrm_sa_info.id.daddr.a6,
				&usersa_id->daddr.a6,
				sizeof(nf_sa->xfrm_sa_info.id.daddr.a6))) {
			return nf_sa;
		}
	}
	return NULL;
}

static inline struct nf_sa
*find_nf_sa_byaddr(xfrm_address_t *saddr, xfrm_address_t *daddr)
{
	struct list_head *l, *tmp;
	struct nf_sa *nf_sa = NULL;
	list_for_each_safe(l, tmp, &nf_sa_list) {
		nf_sa	= (struct nf_sa *)l;
		if (nf_sa->xfrm_sa_info.family == AF_INET &&
			nf_sa->xfrm_sa_info.saddr.a4 == saddr->a4 &&
			nf_sa->xfrm_sa_info.id.daddr.a4 == daddr->a4) {
			return nf_sa;
		} else if (nf_sa->xfrm_sa_info.family == AF_INET6 &&
			!memcmp(&nf_sa->xfrm_sa_info.id.daddr.a6,
				&daddr->a6,
				sizeof(nf_sa->xfrm_sa_info.id.daddr.a6)) &&
			!memcmp(&nf_sa->xfrm_sa_info.saddr.a6,
				&saddr->a6,
				sizeof(nf_sa->xfrm_sa_info.saddr.a6))) {
			return nf_sa;
			}
	}
	return NULL;
}

static inline struct nf_pol
*find_nf_pol_bysel_list(struct xfrm_selector *sel, struct list_head *pol_list)
{

	struct list_head *p, *tmp;
	struct nf_pol *nf_pol = NULL;
	list_for_each_safe(p, tmp, pol_list) {
		nf_pol = (struct nf_pol *)p;
		if (!memcmp(&nf_pol->xfrm_pol_info.sel, sel,
			sizeof(nf_pol->xfrm_pol_info.sel))) {
			return nf_pol;
		}
	}
	return NULL;
}

static inline void
set_offload_dir(struct nf_sa *nf_sa, int dir, struct list_head **pol_list)
{
	if (dir == XFRM_POLICY_OUT) {
		*pol_list = &nf_sa->out_pols;
	} else if (dir == XFRM_POLICY_IN) {
		*pol_list = &nf_sa->in_pols;
	}
}

static inline struct nf_pol
*find_nf_pol_bysel(struct xfrm_selector *sel, int dir)
{
	struct list_head *l, *pol_list;
	struct nf_sa *nf_sa;
	struct nf_pol *nf_pol;
	list_for_each(l, &nf_sa_list) {
		nf_sa = (struct nf_sa *)l;
		set_offload_dir(nf_sa, dir, &pol_list);
		nf_pol = find_nf_pol_bysel_list(sel, pol_list);
		if (nf_pol)
			return nf_pol;
	}
	return NULL;
}

static inline int match_pol_tmpl(struct nf_pol *nf_pol,
				struct nf_sa *nf_sa)
{
	if (nf_sa->xfrm_sa_info.family == AF_INET &&
		nf_pol->sa_saddr.a4 == nf_sa->xfrm_sa_info.saddr.a4 &&
		nf_pol->sa_daddr.a4 == nf_sa->xfrm_sa_info.id.daddr.a4)
		return 1;
	if (nf_sa->xfrm_sa_info.family == AF_INET6 &&
		!memcmp(&nf_pol->sa_saddr.a6,
			&nf_sa->xfrm_sa_info.saddr.a6,
			sizeof(nf_pol->sa_saddr.a6)) &&
		!memcmp(&nf_pol->sa_daddr.a6,
			&nf_sa->xfrm_sa_info.id.daddr.a6,
			sizeof(nf_pol->sa_saddr.a6)))
		return 1;
	return 0;
}

static inline void move_pols_to_pending(struct list_head *pol_list)
{
	struct list_head *l, *tmp;
	struct nf_pol *pol;
	list_for_each_safe(l, tmp, pol_list) {
		pol = (struct nf_pol *)l;
		list_del(&pol->list);
		list_add(&pol->list, &pending_sp);
	}
}

static inline int flush_nf_sa(void)
{
	struct nf_ipsec_sa_del_inargs sa_del_in;
	struct nf_ipsec_sa_del_outargs sa_del_out;
	struct list_head *l, *ltmp;
	struct list_head *p, *ptmp;
	struct nf_sa *nf_sa;
	struct nf_pol *nf_pol;
	int ret  = 0;
	list_for_each_safe(l, ltmp, &nf_sa_list) {
		nf_sa = (struct nf_sa *)l;

		memset(&sa_del_in, 0, sizeof(sa_del_in));
		memset(&sa_del_out, 0, sizeof(sa_del_out));

		sa_del_in.dir = nf_sa->dir;
		sa_del_in.sa_id.spi = nf_sa->spi;
		sa_del_in.sa_id.protocol = nf_sa->protocol;
		sa_del_in.sa_id.dest_ip = nf_sa->dest_ip;

		ret = nf_ipsec_sa_del(0,
				&sa_del_in,
				0,
				&sa_del_out,
				NULL);
		/* TODO - err handling */
		list_for_each_safe(p, ptmp, &nf_sa->in_pols) {
			nf_pol = (struct nf_pol *)p;
			list_del(&nf_pol->list);
			list_add_tail(&nf_pol->list, &pending_sp);
		}

		list_for_each_safe(p, ptmp, &nf_sa->out_pols) {
			nf_pol = (struct nf_pol *)p;
			list_del(&nf_pol->list);
			list_add_tail(&nf_pol->list, &pending_sp);
		}
		list_del(&nf_sa->list);
		free(nf_sa->sa_params.crypto_params.auth_key);
		free(nf_sa->sa_params.crypto_params.cipher_key);
		free(nf_sa);

	}
	return ret;
}

static inline int flush_nf_policies(void)
{
	struct nf_ipsec_spd_del_inargs	spd_in;
	struct nf_ipsec_spd_del_outargs	spd_out;
	struct list_head *l, *ltmp;
	struct list_head *p, *ptmp;
	struct nf_sa *nf_sa;
	struct nf_pol *nf_pol;
	int ret  = 0;

	list_for_each_safe(l, ltmp, &nf_sa_list) {
		nf_sa = (struct nf_sa *)l;
		/* TODO - err handling */
		list_for_each_safe(p, ptmp, &nf_sa->in_pols) {
			nf_pol = (struct nf_pol *)p;
			list_del(&nf_pol->list);
			free(nf_pol);
		}

		/* TODO - err handling */
		list_for_each_safe(p, ptmp, &nf_sa->out_pols) {
			nf_pol = (struct nf_pol *)p;

			memset(&spd_in, 0, sizeof(spd_in));
			spd_in.policy_id = nf_pol->policy_id;
			spd_in.dir	 = nf_pol->dir;

			ret = nf_ipsec_spd_del(0, &spd_in, 0,
					&spd_out, NULL);

			if (ret != 0) {
				error(0, ret, "Failed to remove OUTBOUND SPD rule");
				return ret;
			}

			list_del(&nf_pol->list);
			free(nf_pol);
		}
	}
	list_for_each_safe(p, ptmp, &pending_sp) {
		nf_pol = (struct nf_pol *)p;
		list_del(&nf_pol->list);
		free(nf_pol);
	}
	return ret;
}

int nl_parse_attrs(struct nlattr *na, int len,
		struct nf_ipsec_sa *sa_params,
		struct xfrm_encap_tmpl *encap)
{
	struct xfrm_algo *cipher_alg = NULL;
	struct xfrm_algo *auth_alg = NULL;
	struct xfrm_encap_tmpl *data = NULL;

	while (NLA_OK(na, len)) {
		switch (na->nla_type) {
		case XFRMA_ALG_AUTH:
			auth_alg = (struct xfrm_algo *)NLA_DATA(na);
			break;
		case XFRMA_ALG_CRYPT:
			cipher_alg = (struct xfrm_algo *)NLA_DATA(na);
			break;
		case XFRMA_ENCAP:
			data = (struct xfrm_encap_tmpl *)NLA_DATA(na);
			memcpy(encap, data, sizeof(struct xfrm_encap_tmpl));
			break;
		  }

		na = NLA_NEXT(na, len);
	}

	if (cipher_alg && auth_alg) {
		sa_params->crypto_params.auth_algo =
				get_auth_alg_by_name(auth_alg->alg_name);
		if (sa_params->crypto_params.auth_algo < 0) {
			fprintf(stderr, "%s:%d: Error getting algorithm. "
				"(auth name: %s)\n", __func__, __LINE__,
				auth_alg->alg_name);
			return -EINVAL;
		}

		sa_params->crypto_params.cipher_algo =
				get_enc_alg_by_name(cipher_alg->alg_name);
		if (sa_params->crypto_params.cipher_algo < 0) {
			fprintf(stderr, "%s:%d: Error getting algorithm. "
				"(cipher name: %s)\n",__func__, __LINE__,
				cipher_alg->alg_name);
			return -EINVAL;
		}
		sa_params->crypto_params.auth_key_len_bits =
				auth_alg->alg_key_len;
		sa_params->crypto_params.auth_key =
				(uint8_t *)auth_alg->alg_key;
		sa_params->crypto_params.cipher_key_len_bits =
				cipher_alg->alg_key_len;
		sa_params->crypto_params.cipher_key =
				(uint8_t *)cipher_alg->alg_key;
	} else {
		fprintf(stderr, "%s:%d: Error: Could not fetch auth or cipher "
			"data. auth_addr: %p cipher_addr: %p\n",
			__func__, __LINE__, auth_alg->alg_key,
			cipher_alg->alg_key);
		return -EINVAL;
	}

	if (unlikely(len))
		fprintf(stderr, "%s:%d: Warning: An error occured while parsing"
			" netlink attributes. Length value is %d\n",
			__func__, __LINE__, len);

	return 0;
}

static inline int alloc_ipsec_algs(struct nf_sa		*nf_sa,
				   struct nf_ipsec_sa	*sa_params)
{

	nf_sa->sa_params.crypto_params.auth_key =
			malloc(sa_params->crypto_params.auth_key_len_bits/8);
	if (!nf_sa->sa_params.crypto_params.auth_key) {
		fprintf(stderr, "Cannot allocate memory for auth_key\n");
		free(nf_sa);
		return -ENOMEM;
	}

	nf_sa->sa_params.crypto_params.cipher_key =
			malloc(sa_params->crypto_params.cipher_key_len_bits/8);
	if (!nf_sa->sa_params.crypto_params.cipher_key) {
		fprintf(stderr, "Cannot allocate memory for cipher_key\n");
		free(nf_sa->sa_params.crypto_params.auth_key);
		free(nf_sa);
		return -ENOMEM;
	}

	memcpy(nf_sa->sa_params.crypto_params.auth_key,
		sa_params->crypto_params.auth_key,
		sa_params->crypto_params.auth_key_len_bits/8);
	memcpy(nf_sa->sa_params.crypto_params.cipher_key,
		sa_params->crypto_params.cipher_key,
		sa_params->crypto_params.cipher_key_len_bits/8);

	return 0;
}

static int process_notif_sa(const struct nlmsghdr	*nh, int len,
			   int				dpa_ipsec_id)
{
	struct xfrm_usersa_info *sa_info;
	struct xfrm_encap_tmpl encap;
	struct nf_ipsec_sa sa_params;
	struct nf_sa *nf_sa;
	struct list_head *l, *tmp, *pol_list = NULL;
	struct nf_pol *nf_pol;
	struct nlattr *na;
	int msg_len = 0;
	int ret = 0;

	if (nh->nlmsg_type == XFRM_MSG_NEWSA)
		TRACE("XFRM_MSG_NEWSA\n");

	sa_info = (struct xfrm_usersa_info *)
		NLMSG_DATA(nh);
	na = (struct nlattr *)(NLMSG_DATA(nh) +
			NLMSG_ALIGN(sizeof(*sa_info)));

#ifdef ENABLE_TRACE
	dump_xfrm_sa_info(sa_info);
#endif

	memset(&encap, 0, sizeof(encap));
	memset(&sa_params, 0, sizeof(sa_params));

	/* get SA */
	/* attributes total length in the nh buffer */
	msg_len = len - (int)na + (int)nh;
	ret = nl_parse_attrs(na, msg_len, &sa_params, &encap);
	if (ret) {
		fprintf(stderr, "An error occured while parsing netlink"
		" attributes. Error: (%d)\n", ret);
		return ret;
	}

	/* create and store nf_sa */
	nf_sa = malloc(sizeof(*nf_sa));
	if (!nf_sa) {
		ret = -ENOMEM;
		fprintf(stderr, "Cannot allocate memory for nf_sa\n");
		return ret;
	}

	nf_sa->xfrm_sa_info = *sa_info;
	nf_sa->sa_params = sa_params;

	ret = alloc_ipsec_algs(nf_sa, &sa_params);

	if (ret) {
		fprintf(stderr, "An error occured during"
			" alloc_ipsec_algs. Error: (%d)\n", ret);
		return ret;
	}

	nf_sa->encap = encap;
	nf_sa->sa_init[XFRM_POLICY_IN]  = false;
	nf_sa->sa_init[XFRM_POLICY_OUT] = false;
	INIT_LIST_HEAD(&nf_sa->list);
	INIT_LIST_HEAD(&nf_sa->in_pols);
	INIT_LIST_HEAD(&nf_sa->out_pols);
	list_add_tail(&nf_sa->list, &nf_sa_list);

	/*for each matching policy perform offloading*/
	list_for_each_safe(l, tmp, &pending_sp) {
		nf_pol = (struct nf_pol *)l;
		if (!match_pol_tmpl(nf_pol, nf_sa))
			continue;
		/*Policy found,
		offload SA and add policy*/
		set_offload_dir(nf_sa,
			nf_pol->xfrm_pol_info.dir, &pol_list);
		assert(pol_list);

		ret = do_offload(dpa_ipsec_id, nf_sa, nf_pol);
		if (ret < 0)
			return ret;

		/* move policy from pending to nf_sa list */
		list_del(&nf_pol->list);
		list_add_tail(&nf_pol->list, pol_list);
	}

	return 0;
}

static int process_del_sa(const struct nlmsghdr *nh)
{
	struct nf_ipsec_sa_del_inargs sa_del_in;
	struct nf_ipsec_sa_del_outargs sa_del_out;
	struct xfrm_usersa_id *usersa_id;
	struct nf_sa *nf_sa;
	struct list_head *pols;
	int ret = 0;

	TRACE("XFRM_MSG_DELSA\n");
	usersa_id = (struct xfrm_usersa_id *)
		NLMSG_DATA(nh);

	nf_sa = find_nf_sa(usersa_id);
	if (unlikely(!nf_sa))
		goto out_del_sa;

	if (nf_sa->dir == NF_IPSEC_INBOUND) {
		pols = &nf_sa->in_pols;
	} else {
		pols = &nf_sa->out_pols;
	}

	/* remove dpa policies and move all policies on pending */
	memset(&sa_del_in, 0, sizeof(sa_del_in));
	memset(&sa_del_out, 0, sizeof(sa_del_out));

	sa_del_in.dir = nf_sa->dir;
	sa_del_in.sa_id.spi = nf_sa->spi;
	sa_del_in.sa_id.protocol = nf_sa->protocol;
	sa_del_in.sa_id.dest_ip = nf_sa->dest_ip;

	ret = nf_ipsec_sa_del(0, &sa_del_in, 0, &sa_del_out, NULL);
	if (ret != -EINPROGRESS && ret != 0) {
		fprintf(stderr, "Failed to remove nf_sa, ret %d\n", ret);
		return ret;
	}

	move_pols_to_pending(pols);
	free(nf_sa->sa_params.crypto_params.cipher_key);
	free(nf_sa->sa_params.crypto_params.auth_key);
	list_del(&nf_sa->list);
	free(nf_sa);

out_del_sa:
	return 0;
}

static int process_flush_sa(void)
{
	int ret = 0;

	ret = flush_nf_sa();
	if (ret) {
		fprintf(stderr, "An error occured during sa flushing %d\n",
			ret);
		return ret;
	}

	return 0;
}

static inline int vif_is_up(void)
{
	int fd, ret;
	struct ifreq ifr;

	TRACE("Get flags for app_conf.vif %s\n", app_conf.vif);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		error(0, errno, "socket error\n");
		return -errno;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, app_conf.vif, IFNAMSIZ-1);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		error(0, errno, "Failed to get flags for VIF interface\n");
		return -errno;
	}

	if (ifr.ifr_flags & IFF_UP) {
		TRACE("VIF %s is up\n", app_conf.vif);
		return 1;
	}

	close(fd);

	TRACE("VIF %s is down\n", app_conf.vif);

	return 0;
}


/*
 * Check if policy is referring an SA with the same tunnel source/destination
 * address as the Virtual inbound interface, i.e check if policy is for this
 * instance
 *
 * Returns:
 *	1 in case policy is for this instance
 *	0 in case policy is not for this instance
 *	Negative errno value representing the encountered error if could not
 *	open socket or if ioctl fails
 */
static inline int policy_is_for_us(xfrm_address_t *tun_addr, int af)
{
	int fd, ret;
	struct ifreq ifr;
	struct in_addr *in_addr;

	if (af == AF_INET) {
		TRACE("Get IP address for app_conf.vif name %s\n",
		      app_conf.vif);

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			error(0, errno, "socket error\n");
			return -errno;
		}

		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name, app_conf.vif, IFNAMSIZ-1);
		ret = ioctl(fd, SIOCGIFADDR, &ifr);
		if (ret < 0) {
			error(0, errno, "Failed to get the IP address\n");
			return -errno;
		}

		close(fd);

		in_addr = &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
		TRACE("IP address for app_conf.vif name %s is %s\n",
			app_conf.vif, inet_ntoa(*in_addr));
		TRACE("Tunnel IP %s\n",
			inet_ntoa(*((struct in_addr *)tun_addr)));

		if (in_addr->s_addr == ((struct in_addr *)tun_addr)->s_addr) {
			TRACE("The policy is for this instance\n");
			return 1;
		} else {
			TRACE("The policy is NOT for this instance\n");
			return 0;
		}
	}

	fprintf(stderr, "Warning: the tunnel address is not from AF_INET\n");

	return -EINVAL;
}

static int process_new_policy(const struct nlmsghdr	*nh,
			      int			dpa_ipsec_id)
{

	struct xfrm_userpolicy_info *pol_info;
	struct list_head *pols = NULL;
	struct nf_sa *nf_sa;
	struct nf_pol *nf_pol, *pol;
	int af;
	xfrm_address_t saddr, daddr, addr;
	int ret = 0;

	memset(&addr, 0, sizeof(addr));

	if (nh->nlmsg_type == XFRM_MSG_NEWPOLICY)
		TRACE("XFRM_MSG_NEWPOLICY\n");
	pol_info = (struct xfrm_userpolicy_info *)
		NLMSG_DATA(nh);

	/* we handle only in/out policies */
	if (pol_info->dir != XFRM_POLICY_OUT && pol_info->dir != XFRM_POLICY_IN)
		return -EBADMSG;

	if (nh->nlmsg_type == XFRM_MSG_UPDPOLICY) {
		/* search policy on all nf_sa lists */
		pol = find_nf_pol_bysel(&pol_info->sel, pol_info->dir);
		if (pol) {
			TRACE("policy already offloaded\n");
			goto out_new_pol;
		}
	}

	trace_xfrm_policy_info(pol_info);

	/* get SA tmpl */
	ret = do_spdget(pol_info->index, &saddr, &daddr, &af);
	if (unlikely(ret)) {
		fprintf(stderr,
			"Policy doesn't exist in kernel SPDB\n");
		goto out_new_pol;
	}

	if (app_conf.ib_loop)
		memcpy(&addr, &saddr, sizeof(saddr));
	else {
		if (pol_info->dir == XFRM_POLICY_OUT)
			memcpy(&addr, &saddr, sizeof(saddr));
		if (pol_info->dir == XFRM_POLICY_IN)
			memcpy(&addr, &daddr, sizeof(saddr));
	}

	/* Check if VIF interface is up and skip policy check if not */
	ret = vif_is_up();
	switch (ret) {
	case 0:
		/* VIF is down */
		goto skip_policy_is_for_us;
	case 1:
		/* VIF is up */
		break;
	default:
		TRACE("Failed to check VIF state\n");
		return 0;
	}

	/* Check if policy is regarding this DPA IPSec instance */
	ret = policy_is_for_us(&addr, af);
	switch (ret) {
	case 0:
		TRACE("Policy not for this instance %d\n", dpa_ipsec_id);
		return 0;
	case 1:
		TRACE("Policy is for this instance %d\n", dpa_ipsec_id);
		break;
	default:
		TRACE("Failed checking policy versus tunnel source\n");
		return 0;
	}

skip_policy_is_for_us:

	/* create dpa pol and fill in fields */
	nf_pol = malloc(sizeof(*nf_pol));
	if (!nf_pol) {
		ret = -ENOMEM;
		fprintf(stderr, "Cannot allocate memory for nf_pol\n");
		return ret;
	}
	memset(nf_pol, 0, sizeof(*nf_pol));
	nf_pol->xfrm_pol_info = *pol_info;
	INIT_LIST_HEAD(&nf_pol->list);
	nf_pol->sa_saddr = saddr;
	nf_pol->sa_daddr = daddr;
	nf_pol->sa_family = af;

	nf_sa = find_nf_sa_byaddr(&saddr, &daddr);

	/* SA not found, add pol on pending */
	if (!nf_sa) {
		list_add_tail(&nf_pol->list, &pending_sp);
		goto out_new_pol;
	}

	set_offload_dir(nf_sa, pol_info->dir, &pols);

	ret = do_offload(dpa_ipsec_id, nf_sa, nf_pol);
	if (ret < 0)
		return ret;

	list_add(&nf_pol->list, pols);

out_new_pol:
	return 0;
}

static int process_del_policy(const struct nlmsghdr *nh)
{
	struct nf_ipsec_spd_del_inargs	spd_del_in;
	struct nf_ipsec_spd_del_outargs	spd_del_out;
	struct xfrm_userpolicy_id *pol_id;
	struct nf_pol *nf_pol;
	int ret = 0;

	pol_id = (struct xfrm_userpolicy_id *) NLMSG_DATA(nh);
	TRACE("XFRM_MSG_DELPOLICY\n");

	/* we handle only in/out policies */
	if (pol_id->dir != XFRM_POLICY_OUT && pol_id->dir != XFRM_POLICY_IN)
		return -EBADMSG;

	/* search policy on all nf_sa lists */
	nf_pol = find_nf_pol_bysel(&pol_id->sel, pol_id->dir);
	if (!nf_pol) {
		/* search policy on pending */
		nf_pol = find_nf_pol_bysel_list(&pol_id->sel,
						&pending_sp);
		assert(nf_pol);
		goto out_del_policy;
	}

	if (nf_pol->xfrm_pol_info.dir == XFRM_POLICY_IN)
		goto out_del_policy;

	trace_nf_policy(nf_pol);

	memset(&spd_del_in, 0, sizeof(spd_del_in));
	spd_del_in.policy_id = nf_pol->policy_id;
	spd_del_in.dir	 = nf_pol->dir;

	ret = nf_ipsec_spd_del(0, &spd_del_in, 0, &spd_del_out, NULL);
	if (ret != 0) {
		fprintf(stderr, "Failed to remove policy index %d\n",
				nf_pol->xfrm_pol_info.index);
		return ret;
	}

out_del_policy:
	list_del(&nf_pol->list);
	free(nf_pol);

	return 0;
}

static int process_flush_policy(void)
{
	int ret;

	TRACE("XFRM_MSG_FLUSHPOLICY\n");
	ret = flush_nf_policies();
	if (ret < 0) {
		fprintf(stderr, "An error occured during policies"
			" flushing %d\n", ret);
		return ret;
	}

	return 0;
}

static int resolve_xfrm_notif(const struct nlmsghdr	*nh,
			       int			len,
			       int			dpa_ipsec_id)
{
	int ret = 0;

	TRACE("Used instance id %d\n", dpa_ipsec_id);

	switch (nh->nlmsg_type) {
	case XFRM_MSG_UPDSA:
		TRACE("XFRM_MSG_UPDSA\n");
	case XFRM_MSG_NEWSA:
		ret = process_notif_sa(nh, len, dpa_ipsec_id);
		break;
	case XFRM_MSG_DELSA:
		ret = process_del_sa(nh);
		break;
	case XFRM_MSG_FLUSHSA:
		TRACE("XFRM_MSG_FLUSHSA\n");
		ret = process_flush_sa();
		break;
	case XFRM_MSG_UPDPOLICY:
		TRACE("XFRM_MSG_UPDPOLICY\n");
	case XFRM_MSG_NEWPOLICY:
		ret = process_new_policy(nh, dpa_ipsec_id);
		break;
	case XFRM_MSG_DELPOLICY:
		ret = process_del_policy(nh);
		break;
	case XFRM_MSG_GETPOLICY:
		TRACE("XFRM_MSG_GETPOLICY\n");
		break;
	case XFRM_MSG_POLEXPIRE:
		TRACE("XFRM_MSG_POLEXPIRE\n");
		break;
	case XFRM_MSG_FLUSHPOLICY:
		ret = process_flush_policy();
		break;
	}

	return ret;
}

static void *xfrm_msg_loop(void *data)
{
	int xfrm_sd;
	int ret;
	int len = 0;
	char buf[4096];	/* XFRM messages receive buf */
	struct iovec iov = { buf, sizeof(buf) };
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;
	int dpa_ipsec_id;
	cpu_set_t cpuset;
	struct sigaction new_action, old_action;
	struct thread_data *thread_data = NULL;

	quit = 0;
	/* get ipsec instance we use */
	thread_data = (struct thread_data *)data;
	dpa_ipsec_id = thread_data->dpa_ipsec_id;

	/* install a signal handler for SIGUSR2 */
	new_action.sa_handler = xfrm_sig_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGUSR2, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGUSR2, &new_action, NULL);

	/* Set this cpu-affinity to CPU 0 */
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (ret != 0) {
		fprintf(stderr,
			"pthread_setaffinity_np(%d) failed, ret=%d\n", 0, ret);
		pthread_exit(NULL);
	}

	xfrm_sd = create_nl_socket(NETLINK_XFRM, XFRMGRP_ACQUIRE |
				   XFRMGRP_EXPIRE |
				   XFRMGRP_SA |
				   XFRMGRP_POLICY |
				   XFRMGRP_REPORT);
	if (xfrm_sd < 0) {
		fprintf(stderr,
			"opening NETLINK_XFRM socket failed, errno %d\n",
			errno);
		pthread_exit(NULL);
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* XFRM notification loop */
	while (!quit) {
		len = recvmsg(xfrm_sd, &msg, 0);
		if (len < 0 && errno != EINTR) {
			fprintf(stderr,
				"error receiving from XFRM socket, errno %d\n",
				errno);
			break;
		} else if (errno == EINTR) /* loop break requested */
			break;

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_ERROR) {
				fprintf(stderr,
					"Netlink error on XFRM socket,"
					" errno %d\n",
					errno);
				break;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI ||
				nh->nlmsg_type == NLMSG_DONE) {
				fprintf(stderr,
					"XFRM multi-part messages not supported\n");
				break;
			}

			ret = resolve_xfrm_notif(nh, len, dpa_ipsec_id);
			if (ret != 0 && ret != -EBADMSG) {
				fprintf(stderr, "Resolve xfrm notification"
					" error %d\n", ret);
				break;
			}
		}
	}

	close(xfrm_sd);
	pthread_exit(NULL);
}

int setup_xfrm_msg_loop(int dpa_ipsec_id)
{
	int ret;

	xfrm_data = malloc(sizeof(*xfrm_data));
	if (!xfrm_data) {
		error(0, ENOMEM, "Cammot allocate XFRM thread data");
		return -ENOMEM;
	}

	xfrm_data->dpa_ipsec_id = dpa_ipsec_id;

	ret = pthread_create(&tid, NULL, xfrm_msg_loop, xfrm_data);
	if (ret)
		error(0, ret, "Failed to create XFRM thread");

	return ret;
}

int teardown_xfrm_msg_loop(void)
{
	int ret;

	quit = 1;

	ret = pthread_kill(tid, SIGUSR2);
	if (ret) {
		error(0, ret, "Failed to send signal to XFRM thread");
		return ret;
	}

	ret = pthread_join(tid, NULL);
	if (ret) {
		error(0, ret, "Failed to join the XFRM thread");
		return ret;
	}

	free(xfrm_data);

	return 0;
}
