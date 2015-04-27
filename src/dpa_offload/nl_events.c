/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

#include <error.h>
#include <pthread.h>
#include <stdbool.h>
#include <signal.h>

#include <netlink/route/rtnl.h>
#include <netlink/route/rule.h>
#include <netlink/route/neighbour.h>

#include "compat.h"
#include "fsl_qman.h"
#include "usdpaa_netcfg.h"
#include "init_nfapi.h"
#include "arp_nfapi.h"
#include "ip4_fwd_nfapi.h"
#include "ip6_fwd_nfapi.h"
#include "nd_nfapi.h"
#include "nl_events.h"

#include "app_common.h"

#define RT_FILE_NAME	"/etc/iproute2/rt_tables"

#define NL_ACT_MAX (__NL_ACT_MAX - 1)

struct rule_filter_cbarg {
	/* route action */
	int action;
	union {
		struct nf_ip4_fwd_route_entry *nfapi_rt_entry;
		struct nf_ip6_fwd_route_entry *nfapi_rt_entry6;
	};
	struct rtnl_route *route;
};

struct route_filter_cbarg {
	/*pointer to matching rule args */
	union {
		struct nf_ip4_fwd_pbr_rule *nfapi_rule;
		struct nf_ip6_fwd_pbr_rule *nfapi_rule6;
	};
	/* rule object */
	struct rtnl_rule *rule;
};

static struct nl_dump_params dump_params = {
	.dp_type = NL_DUMP_LINE,
};

static pthread_t tid;
static volatile sig_atomic_t quit;
static struct nl_cache_mngr *cache_mngr;
static struct nl_cache *neigh_cache, *route_cache, *rule_cache;
/* local routing table */
static int rt_local;

/* move them from here */
struct nf_ipfwd_resources *ip4fwd_route_nf_res,
		    *ip4fwd_rule_nf_res,
		    *ip6fwd_route_nf_res,
		    *ip6fwd_rule_nf_res;

const char *nl_act_str[] = {
	"NL_ACT_NEW",
	"NL_ACT_DEL",
	"NL_ACT_GET",
	"NL_ACT_SET",
	"NL_ACT_CHANGE"
};

static void nl_sig_handler(int signum)
{
	TRACE("netlink signal handler caught signal %d\n", signum);
	if (signum == SIGUSR1)
		quit = 1;
}

static inline void ip_mask(uint8_t *mask, int prefixlen)
{
	static const uint8_t mask_bits[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8,
					    0xfc, 0xfe, 0xff};
	uint8_t bit, off;

	off = prefixlen / 8;
	bit = prefixlen % 8;
	while (off--)
		*mask++ = 0xff;
	if (bit)
		*mask = mask_bits[bit];
}

static inline const char *nl_act_tostr(int nl_act)
{
	if (nl_act < NL_ACT_NEW ||
	    nl_act > NL_ACT_CHANGE)
		return NULL;
	return nl_act_str[nl_act-1];
}

static inline int is_shmac(char *ifname)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;
	for (i = 0; i < gbl_init->netcfg->num_ethports; i++) {
		port_cfg = &gbl_init->netcfg->port_cfg[i];
		if (!strcmp(port_cfg->fman_if->shared_mac_info.shared_mac_name,
		    ifname)) {
			return port_cfg->fman_if->shared_mac_info.is_shared_mac;
		}
	}
	return 0;
}

static inline int
fill_nfapi_rule_params(struct rtnl_rule *rule,
		       void *nfapi_rule, int family)
{
	struct nl_addr *addr;
	uint32_t *addr_b, sz;
	char *ifname;
	struct nf_ip4_fwd_pbr_rule *p_nfapi_rule;
	struct nf_ip6_fwd_pbr_rule *p_nfapi_rule6;
	bool src = false, dst = false;

	if (family == AF_INET) {
		p_nfapi_rule = nfapi_rule;
		memset(p_nfapi_rule, 0, sizeof(*p_nfapi_rule));
		p_nfapi_rule->priority = rtnl_rule_get_prio(rule);
		addr = rtnl_rule_get_dst(rule);
		if (addr) {
			addr_b = (uint32_t *)nl_addr_get_binary_addr(addr);
			p_nfapi_rule->dst_addr = *addr_b;
			p_nfapi_rule->dstip_prefix =
						nl_addr_get_prefixlen(addr);
			dst = true;
		}
		addr = rtnl_rule_get_src(rule);
		if (addr) {
			addr_b = (uint32_t *)nl_addr_get_binary_addr(addr);
			p_nfapi_rule->src_addr = *addr_b;
			p_nfapi_rule->srcip_prefix =
						nl_addr_get_prefixlen(addr);
			src = true;
		}

		/*
		 * if both addresses are null it means that src, dst and
		 * masks will be 0
		 * we do not want to offload such a rule
		 */
		if (!dst && !src)
			return -EINVAL;

		p_nfapi_rule->tos = rtnl_rule_get_dsfield(rule);
		ifname = rtnl_rule_get_iif(rule);
		if (ifname && !is_shmac(ifname))
			return -EINVAL;
		if (ifname)
			p_nfapi_rule->in_ifid = if_nametoindex(ifname);
		ifname = rtnl_rule_get_oif(rule);
		if (ifname)
			p_nfapi_rule->out_ifid = if_nametoindex(ifname);
		p_nfapi_rule->opaque = rtnl_rule_get_mark(rule);
		p_nfapi_rule->opaque_mask = rtnl_rule_get_mask(rule);
		p_nfapi_rule->rt_table_no = rtnl_rule_get_table(rule);

	} else {
		p_nfapi_rule6 = nfapi_rule;
		sz = sizeof(struct in6_addr);
		memset(p_nfapi_rule6, 0, sizeof(*p_nfapi_rule6));
		p_nfapi_rule6->priority = rtnl_rule_get_prio(rule);
		addr = rtnl_rule_get_dst(rule);
		if (addr) {
			addr_b = (uint32_t *)nl_addr_get_binary_addr(addr);
			memcpy(p_nfapi_rule6->dst_addr.b_addr, addr_b, sz);
			p_nfapi_rule6->dstip_prefix =
						nl_addr_get_prefixlen(addr);
			dst = true;
		}
		addr = rtnl_rule_get_src(rule);
		if (addr) {
			addr_b = (uint32_t *)nl_addr_get_binary_addr(addr);
			memcpy(p_nfapi_rule6->src_addr.b_addr, addr_b, sz);
			p_nfapi_rule6->srcip_prefix =
						nl_addr_get_prefixlen(addr);
			src = true;
		}

		/*
		 * if both addresses are null it means that src, dst and
		 * masks will be 0
		 * we do not want to offload such a rule
		 */
		if (!dst && !src)
			return -EINVAL;

		p_nfapi_rule6->tc = rtnl_rule_get_dsfield(rule);
		ifname = rtnl_rule_get_iif(rule);
		if (ifname && !is_shmac(ifname))
			return -EINVAL;
		if (ifname)
			p_nfapi_rule6->in_ifid = if_nametoindex(ifname);
		ifname = rtnl_rule_get_oif(rule);
		if (ifname)
			p_nfapi_rule6->out_ifid = if_nametoindex(ifname);
		p_nfapi_rule6->opaque = rtnl_rule_get_mark(rule);
		p_nfapi_rule6->opaque_mask = rtnl_rule_get_mask(rule);
		p_nfapi_rule6->rt_table_no = rtnl_rule_get_table(rule);

	}
	return 0;
}

static inline int
fill_nfapi_route_params(struct rtnl_route *route,
			void *nfapi_route,
			int family)
{
	struct nl_addr *dst_addr, *gw_addr;
	struct rtnl_nexthop *nh;
	char ifname[IFNAMSIZ];
	int nnh, i, ifid, sz; /* number of nexthops */
	uint32_t *dst_addr_b, *gw_addr_b;
	uint32_t rt_table;
	uint32_t path_mtu;
	struct nf_ip4_fwd_route_entry *p_nfapi_route;
	struct nf_ip6_fwd_route_entry *p_nfapi_route6;

	if (family == AF_INET) {
		p_nfapi_route = nfapi_route;
		/* fill in params and call NF API */
		memset(p_nfapi_route, 0, sizeof(*p_nfapi_route));
		dst_addr = rtnl_route_get_dst(route);
		if (!dst_addr)
			return -EINVAL;

		dst_addr_b = (uint32_t *)nl_addr_get_binary_addr(dst_addr);
		p_nfapi_route->dst_addr = *dst_addr_b;
		p_nfapi_route->tos = rtnl_route_get_tos(route);
		p_nfapi_route->prefix_length = nl_addr_get_prefixlen(dst_addr);

		rt_table = rtnl_route_get_table(route);
		p_nfapi_route->rt_table_id = rt_table;
		rtnl_route_get_metric(route, RTAX_MTU,
				     &path_mtu);
		p_nfapi_route->path_mtu = (uint16_t) path_mtu;
		nnh = rtnl_route_get_nnexthops(route);
		p_nfapi_route->num_gw = nnh;
		for (i = 0; i < nnh && i < NF_IP4_FWD_MAX_ECMP_GWS; i++) {
			nh = rtnl_route_nexthop_n(route, i);
			ifid = rtnl_route_nh_get_ifindex(nh);
			/* at least one nh is not ours */
			if (!if_indextoname(ifid, ifname) || !is_shmac(ifname))
				return -EINVAL;

			p_nfapi_route->gw_info[i].flags =
						    rtnl_route_nh_get_flags(nh);
			p_nfapi_route->gw_info[i].out_ifid =
						  rtnl_route_nh_get_ifindex(nh);
			gw_addr = rtnl_route_nh_get_gateway(nh);
			if (!gw_addr)
				return -EINVAL;

			gw_addr_b =
				  (uint32_t *)nl_addr_get_binary_addr(gw_addr);
			p_nfapi_route->gw_info[i].gw_ipaddr = *gw_addr_b;
			p_nfapi_route->gw_info[i].weight =
						   rtnl_route_nh_get_weight(nh);
		}

	} else {
		p_nfapi_route6 = nfapi_route;
		/* fill in params and call NF API */
		sz = sizeof(struct in6_addr);
		memset(p_nfapi_route6, 0, sizeof(*p_nfapi_route6));
		dst_addr = rtnl_route_get_dst(route);
		if (!dst_addr)
			return -EINVAL;

		dst_addr_b = (uint32_t *)nl_addr_get_binary_addr(dst_addr);
		memcpy(p_nfapi_route6->dst_addr.w_addr, dst_addr_b, sz);
		p_nfapi_route6->prefix_len = nl_addr_get_prefixlen(dst_addr);
		p_nfapi_route6->tc = rtnl_route_get_tos(route);
		rt_table = rtnl_route_get_table(route);
		p_nfapi_route6->rt_table_id = rt_table;
		rtnl_route_get_metric(route, RTAX_MTU,
				      &path_mtu);
		p_nfapi_route6->path_mtu = (uint16_t) path_mtu;
		nnh = rtnl_route_get_nnexthops(route);
		p_nfapi_route6->num_gw = nnh;
		for (i = 0; i < nnh && i < NF_IP4_FWD_MAX_ECMP_GWS; i++) {
			nh = rtnl_route_nexthop_n(route, i);
			ifid = rtnl_route_nh_get_ifindex(nh);
			/* at least one nh is not ours */
			if (!if_indextoname(ifid, ifname) || !is_shmac(ifname))
				return -EINVAL;

			p_nfapi_route6->gw_info[i].flags =
						    rtnl_route_nh_get_flags(nh);
			p_nfapi_route6->gw_info[i].out_ifid =
						  rtnl_route_nh_get_ifindex(nh);
			gw_addr = rtnl_route_nh_get_gateway(nh);
			if (!gw_addr)
				return -EINVAL;

			gw_addr_b =
				   (uint32_t *)nl_addr_get_binary_addr(gw_addr);
			memcpy(p_nfapi_route6->gw_info[i].gw_ipaddr.w_addr,
				gw_addr_b, sz);
			p_nfapi_route6->gw_info[i].weight =
						   rtnl_route_nh_get_weight(nh);
		}

	}

	return 0;
}

static inline int fill_nfapi_arp_params(struct rtnl_neigh *neigh,
					 void *nfapi_arp, int family)
{
	struct nl_addr *addr;
	int if_idx, state;
	char ifname[IFNAMSIZ];
	char *lladdr = NULL;
	uint32_t *p32;
	struct nf_arp_entry *p_nfapi_arp;
	struct nf_nd_entry *p_nfapi_arp6;

	if_idx = rtnl_neigh_get_ifindex(neigh);
	memset(ifname, 0, sizeof(ifname));
	if (!if_indextoname(if_idx, ifname) || !is_shmac(ifname))
		return -EINVAL;

	/* check state */
	state = rtnl_neigh_get_state(neigh);
	if (!(state & (NUD_PERMANENT|NUD_REACHABLE)) &&
	    !(state & (NUD_STALE|NUD_FAILED)))
		return -EINVAL;

	if (family == AF_INET) {
		p_nfapi_arp = (struct nf_arp_entry *)nfapi_arp;
		p_nfapi_arp->arp_id.ifid = if_idx;
		p_nfapi_arp->state = state;
		addr = rtnl_neigh_get_dst(neigh);
		p32 = (uint32_t *)nl_addr_get_binary_addr(addr);
		memcpy(&p_nfapi_arp->arp_id.ip_address, p32,
			sizeof(struct in_addr));
		addr = rtnl_neigh_get_lladdr(neigh);
		if (addr)
			lladdr = nl_addr_get_binary_addr(addr);
		if (lladdr)
			memcpy(p_nfapi_arp->mac_addr, lladdr,
			       sizeof(p_nfapi_arp->mac_addr));
	} else {
		p_nfapi_arp6 = (struct nf_nd_entry *)nfapi_arp;
		p_nfapi_arp6->nd_id.ifid = if_idx;
		p_nfapi_arp6->state = state;
		addr = rtnl_neigh_get_dst(neigh);
		p32 = (uint32_t *)nl_addr_get_binary_addr(addr);
		memcpy(p_nfapi_arp6->nd_id.ip_address.w_addr, p32,
			sizeof(struct in6_addr));
		addr = rtnl_neigh_get_lladdr(neigh);
		if (addr)
			lladdr = nl_addr_get_binary_addr(addr);
		if (lladdr)
			memcpy(p_nfapi_arp6->mac_addr, lladdr,
			       sizeof(p_nfapi_arp->mac_addr));

	}
	return 0;

}

static void rule_filter_cb(struct nl_object *nl_obj, void *arg)
{
	struct rtnl_rule *rule = (struct rtnl_rule *)nl_obj;
	struct rule_filter_cbarg *cbarg = (struct rule_filter_cbarg *)arg;
	struct nf_ip4_fwd_pbr_rule nfapi_rule;
	struct nf_ip4_fwd_rule_outargs out_args;
	struct nf_ip4_fwd_route_outargs route_out_args;
	struct nf_ip6_fwd_pbr_rule nfapi_rule6;
	struct nf_ip6_fwd_pbr_rule_outargs out_args6;
	struct nf_ip6_fwd_route_outargs route_out_args6;
	int32_t ret;
	int family;

	family = rtnl_rule_get_family(rule);
	if (family == AF_INET)
		ret = fill_nfapi_rule_params(rule, &nfapi_rule, family);
	else
		ret = fill_nfapi_rule_params(rule, &nfapi_rule6, family);

	if (ret < 0)
		return;

	nl_object_dump(nl_obj, &dump_params);
	if (cbarg->action == NL_ACT_NEW) {
		/* rule not offloaded */
		if (!nl_object_is_marked(nl_obj)) {

			if (family == AF_INET)
				ret = nf_ip4_fwd_pbr_rule_add(0, &nfapi_rule,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
						      &out_args,
						      NULL);
			else
				ret = nf_ip6_fwd_pbr_rule_add(0, &nfapi_rule6,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
						      &out_args6,
						      NULL);
			/* rule was offloaded */
			if (!ret)
				nl_object_mark(nl_obj);
		}
		/* route already offloaded */
		if (nl_object_is_marked((struct nl_object *)(cbarg->route)))
			return;

		family = rtnl_route_get_family(cbarg->route);

		if (family == AF_INET) {
			ret = nf_ip4_fwd_route_add(0, cbarg->nfapi_rt_entry,
					     NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					     &route_out_args,
					     NULL);
			printf("%s %s : nf_ip4_fwd_route_add\n",
				__func__, nl_act_tostr(cbarg->action));
		} else {
			ret = nf_ip6_fwd_route_add(0, cbarg->nfapi_rt_entry6,
					     NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					     &route_out_args6,
					     NULL);
			printf("%s %s : nf_ip6_fwd_route_add\n",
				__func__, nl_act_tostr(cbarg->action));
		}
		/* route was offloaded */
		if (!ret)
			nl_object_mark((struct nl_object *)(cbarg->route));

	}
	/*
	if (cbarg->action == NL_ACT_CHANGE) {
	}
	*/
}

static int run_rule_filter(struct nl_cache *cache __maybe_unused,
			   struct rtnl_route *rt,
			   void *nfapi_rt_entry,
			   int action)
{
	struct rule_filter_cbarg cbarg;
	struct rtnl_rule *rule_filter;
	int rt_family;

	/* filter rules which select the table containing this route */
	rule_filter = rtnl_rule_alloc();
	if (!rule_filter) {
		fprintf(stderr, "rtnl_rule_alloc failed\n");
		return -ENOMEM;
	}

	rt_family = rtnl_route_get_family(rt);

	rtnl_rule_set_family(rule_filter, rt_family);
	if (rt_family == AF_INET) {
		cbarg.nfapi_rt_entry = nfapi_rt_entry;
		rtnl_rule_set_table(rule_filter,
				   cbarg.nfapi_rt_entry->rt_table_id);
	}
	else {
		cbarg.nfapi_rt_entry6 = nfapi_rt_entry;
		rtnl_rule_set_table(rule_filter,
				   cbarg.nfapi_rt_entry6->rt_table_id);
	}

	rtnl_rule_set_action(rule_filter, FR_ACT_TO_TBL);
	cbarg.action = action;

	cbarg.route = rt;
	nl_cache_foreach_filter(rule_cache, (struct nl_object *)rule_filter,
				rule_filter_cb, &cbarg);
	rtnl_rule_put(rule_filter);
	return 0;
}

static void route_filter_cb(struct nl_object *nl_obj, void *arg)
{
	struct rtnl_route *rt = (struct rtnl_route *)nl_obj;
	struct route_filter_cbarg *cbarg = (struct route_filter_cbarg *)arg;
	struct rtnl_nexthop *nh;
	char ifname[IFNAMSIZ];
	int nnh, i, ifid, ret;
	struct nf_ip4_fwd_route_entry nfapi_rt_entry;
	struct nf_ip4_fwd_route_outargs out_args;
	struct nf_ip4_fwd_rule_outargs rule_out_args;
	struct nf_ip6_fwd_route_entry nfapi_rt_entry6;
	struct nf_ip6_fwd_route_outargs out_args6;
	struct nf_ip6_fwd_pbr_rule_outargs rule_out_args6;
	int family;

	/*loop over nexthops and check if all are our interfaces */
	nnh = rtnl_route_get_nnexthops(rt);
	for (i = 0; i < nnh && i < NF_IP4_FWD_MAX_ECMP_GWS; i++) {
		nh = rtnl_route_nexthop_n(rt, i);
		ifid = rtnl_route_nh_get_ifindex(nh);
		/* at least one nh is not ours */
		if (!if_indextoname(ifid, ifname) || !is_shmac(ifname))
			return;
	}

	family = rtnl_rule_get_family(cbarg->rule);
	/* we found a route */
	if (!nl_object_is_marked((struct nl_object *)(cbarg->rule))) {
		if (family == AF_INET)
			ret = nf_ip4_fwd_pbr_rule_add(0, cbarg->nfapi_rule,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &rule_out_args,
					      NULL);
		else
			ret = nf_ip6_fwd_pbr_rule_add(0, cbarg->nfapi_rule6,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &rule_out_args6,
					      NULL);

		/* rule was offloaded */
		if (!ret)
			nl_object_mark((struct nl_object *)(cbarg->rule));
	}

	/* route already offloaded */
	if (nl_object_is_marked((struct nl_object *)rt))
		return;

	family = rtnl_route_get_family(rt);

	if (family == AF_INET) {
		/* route not offloaded */
		ret = fill_nfapi_route_params(rt, &nfapi_rt_entry, family);
		if (ret < 0)
			return;

		ret = nf_ip4_fwd_route_add(0, &nfapi_rt_entry,
					   NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					   &out_args,
					   NULL);
	} else {
		/* route not offloaded */
		ret = fill_nfapi_route_params(rt, &nfapi_rt_entry6, family);
		if (ret < 0)
			return;

		ret = nf_ip6_fwd_route_add(0, &nfapi_rt_entry6,
					   NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					   &out_args6,
					   NULL);
	}
	/* route was offoaded */
	if (!ret)
		nl_object_mark((struct nl_object *)rt);

}

static int run_route_filter(struct nl_cache *cache,
			      void *nfapi_rule,
			      struct rtnl_rule *rule)
{
	struct rtnl_route *rt_filter;
	struct route_filter_cbarg cbarg;
	int found = 0;
	int family;

	rt_filter = rtnl_route_alloc();
	if (!rt_filter) {
		fprintf(stderr, "rtnl_route_alloc failed\n");
		return -ENOMEM;
	}

	family = rtnl_rule_get_family(rule);
	if (family == AF_INET) {
		cbarg.nfapi_rule = nfapi_rule;
		rtnl_route_set_table(rt_filter, cbarg.nfapi_rule->rt_table_no);
	} else {
		cbarg.nfapi_rule6 = nfapi_rule;
		rtnl_route_set_table(rt_filter, cbarg.nfapi_rule6->rt_table_no);

	}

	cbarg.rule = rule;
	nl_cache_foreach_filter(cache, (struct nl_object *)rt_filter,
				route_filter_cb, &cbarg);
	rtnl_route_put(rt_filter);

	return found;
}

void neigh_cache_change_cb(struct nl_cache *cache __maybe_unused,
			   struct nl_object *nl_obj,
			   int action,
			   void *arg)
{
	struct rtnl_neigh *neigh;
	struct nf_arp_entry nf_arp_in;
	struct nf_arp_entry_identifier nf_arp_del_params;
	/*
	 * Variable not used anymore, function taken out from API.
	 * struct nf_arp_entry nf_arp_mod_params;
	 */
	struct nf_nd_entry_identifier nf_nd_del_params;
	/*
	 * Variable not used anymore, function taken out from API.
	 * struct nf_nd_entry nf_nd_mod_params;
	 */
	struct nf_arp_outargs nf_arp_out;
	struct nf_nd_entry nf_arp_in6;
	struct nf_nd_outargs nf_arp_out6;
	int ret, family;

	neigh  = (struct rtnl_neigh *) nl_obj;
	route_cache  = (struct nl_cache *)arg;

	family = rtnl_neigh_get_family(neigh);

	if (family == AF_INET) {
		ret = fill_nfapi_arp_params(neigh, &nf_arp_in, family);
		if (ret < 0)
			return;
	} else {
		ret = fill_nfapi_arp_params(neigh, &nf_arp_in6, family);
		if (ret < 0)
			return;
	}

	printf("%s : %s\n", __func__, nl_act_tostr(action));
	nl_object_dump(nl_obj, &dump_params);

	if (family == AF_INET) {
		/* Add or modify */
		if (nf_arp_in.state & (NUD_PERMANENT|NUD_REACHABLE)) {
			struct nf_arp_get_outargs nf_arp_get_out;
			struct nf_arp_get_inargs nf_arp_get_params;

			/* Check if this ARP entry was already offloaded: */
			nf_arp_get_params.ifid = nf_arp_in.arp_id.ifid;
			nf_arp_get_params.ip_address =
						nf_arp_in.arp_id.ip_address;
			nf_arp_get_params.operation = NF_ARP_GET_EXACT;
			ret = nf_arp_entry_get(0, &nf_arp_get_params,
					NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					&nf_arp_get_out, NULL);
			if (ret)
				/* Not offloaded. Offload it now */
				ret = nf_arp_entry_add(0, &nf_arp_in,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &nf_arp_out, NULL);
			else {
				/* Already offloaded. Modify */
				/*
				 * TODO: the modify entry was taken away in
				 * NFAPI v0.5
				 * Fix the problem and then uncomment this or
				 * use del/add to modify it.
				 */
#ifdef NFAPI_ARP_ENTRY_MODIFY
				memcpy(&nf_arp_mod_params, &nf_arp_in,
					sizeof(nf_arp_in));
				printf("%s %s : nf_arp_modify_entry\n",
					__func__, nl_act_tostr(action));
				ret = nf_arp_entry_modify(0,&nf_arp_mod_params,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &nf_arp_out, NULL);
#else
				printf("%s: nf_arp_entry_modify taken out from API\n",
					__func__);
				ret = -ENOSYS;
#endif
			}
		}

		/* Delete */
		if ((nf_arp_in.state & (NUD_STALE|NUD_FAILED)) ||
				(action == NL_ACT_DEL)) {
			action = NL_ACT_DEL;
			nf_arp_del_params.ifid = nf_arp_in.arp_id.ifid;
			memcpy(&nf_arp_del_params.ip_address,
				&nf_arp_in.arp_id.ip_address,
				sizeof(struct in_addr));
			ret = nf_arp_entry_del(0, &nf_arp_del_params,
					NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					&nf_arp_out, NULL);
		}

		if (!ret)
			printf("%s IPv4 ARP entry\n", nl_act_tostr(action));
	} else {
		/* Add or modify */
		if (nf_arp_in6.state & (NUD_PERMANENT|NUD_REACHABLE)) {
			struct nf_nd_get_inargs nf_nd_get_params;
			struct nf_nd_get_outargs nf_nd_get_out;

			nf_nd_get_params.ifid = nf_arp_in6.nd_id.ifid;
			memcpy(&nf_nd_get_params.ip_address,
				&nf_arp_in6.nd_id.ip_address,
				sizeof(struct nf_ipv6_addr));
			nf_nd_get_params.operation = NF_ND_GET_EXACT;
			ret = nf_nd_entry_get(0, &nf_nd_get_params,
					NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					&nf_nd_get_out, NULL);
			if (ret)
				/* Not offloaded. Offload it now */
				ret = nf_nd_entry_add(0, &nf_arp_in6,
					NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					&nf_arp_out6, NULL);
			else {
				/* Already offloaded. Modify */
				/*
				 * TODO: the modify entry was taken away in
				 * NFAPI v0.5
				 * Fix the problem and then uncomment this or
				 * use del/add to modify it.
				 */
#ifdef NFAPI_ARP_ENTRY_MODIFY
				memcpy(&nf_nd_mod_params, &nf_arp_in6,
					sizeof(nf_arp_in6));
				printf("%s %s : nf_arp_modify_entry\n",
					__func__, nl_act_tostr(action));
				ret = nf_nd_modify_entry(0, &nf_nd_mod_params,
					NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					&nf_arp_out6, NULL);
#else
				printf("%s: nf_nd_modify_entry taken out from API\n",
					__func__);
				ret = -ENOSYS;
#endif
			}
		}

		/* Delete */
		if ((nf_arp_in6.state & (NUD_STALE|NUD_FAILED)) ||
				(action == NL_ACT_DEL)) {
			action = NL_ACT_DEL;
			nf_nd_del_params.ifid = nf_arp_in6.nd_id.ifid;
			memcpy(nf_nd_del_params.ip_address.w_addr,
			       nf_arp_in6.nd_id.ip_address.w_addr,
			       sizeof(struct in_addr));
			ret = nf_nd_entry_del(0, &nf_nd_del_params,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &nf_arp_out6, NULL);;
		}

		if (!ret)
			printf("%s IPv6 neighbour entry\n",
							nl_act_tostr(action));
	}
}

void route_cache_change_cb(struct nl_cache *cache __maybe_unused,
			   struct nl_object *nl_obj,
			   int action,
			   void *arg __maybe_unused)
{
	struct rtnl_route *rt;
	int rt_table, ret;
	struct nf_ip4_fwd_route_entry nfapi_rt_entry;
	struct nf_ip4_fwd_route_entry_del nfapi_rt_del_param;
	struct nf_ip6_fwd_route_entry_del nfapi_rt_del_param6;
	struct nf_ip4_fwd_route_entry_mod nfapi_rt_mod_param;
	struct nf_ip6_fwd_route_entry_mod nfapi_rt_mod_param6;
	struct nf_ip4_fwd_route_outargs out_args;
	struct nf_ip6_fwd_route_entry nfapi_rt_entry6;
	struct nf_ip6_fwd_route_outargs out_args6;
	int rt_family;

	rt = (struct rtnl_route *)nl_obj;
	rt_table = rtnl_route_get_table(rt);
	if (rt_table == rt_local)
		return;

	rt_family = rtnl_route_get_family(rt);

	if (action != NL_ACT_NEW &&
	    action != NL_ACT_CHANGE &&
	    action != NL_ACT_DEL)
		return;

	if (rt_family == AF_INET)
		ret = fill_nfapi_route_params(rt, &nfapi_rt_entry, rt_family);
	else
		ret = fill_nfapi_route_params(rt, &nfapi_rt_entry6, rt_family);

	if (ret < 0)
		return;

	switch (action) {
	case NL_ACT_NEW:
		/* Is the route already offloaded? */
		if (nl_object_is_marked(nl_obj))
			return;

		nl_object_dump(nl_obj, &dump_params);

		if (rt_family == AF_INET) {
			ret = nf_ip4_fwd_route_add(0, &nfapi_rt_entry,
				     NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
				     &out_args,
				     NULL);
			if (!ret)
				printf("%s IPv4 route in RT table %d\n",
					nl_act_tostr(action),
					nfapi_rt_entry.rt_table_id);
		} else {
			ret = nf_ip6_fwd_route_add(0, &nfapi_rt_entry6,
				     NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
				     &out_args6,
				     NULL);
			if (!ret)
				printf("%s IPv6 route in RT table %d\n",
					nl_act_tostr(action),
					nfapi_rt_entry6.rt_table_id);
		}

		if (!ret)
			/* route was offloaded */
			nl_object_mark(nl_obj);
		else if (ret != -ENOENT)
				error(0, -ret, "Failed to add route");

		break;
	case NL_ACT_DEL:
		/* Check if the route is offloaded */
		if (!nl_object_is_marked(nl_obj))
			return;

		nl_object_dump(nl_obj, &dump_params);

		if (rt_family == AF_INET) {
			nfapi_rt_del_param.dst_addr = nfapi_rt_entry.dst_addr;
			nfapi_rt_del_param.tos = nfapi_rt_entry.tos;
			nfapi_rt_del_param.rt_table_id =
						     nfapi_rt_entry.rt_table_id;
			ret = nf_ip4_fwd_route_delete(0, &nfapi_rt_del_param,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &out_args, NULL);
			if (!ret)
				printf("%s IPv4 route from RT table %d\n",
					nl_act_tostr(action),
					nfapi_rt_del_param.rt_table_id);
		} else {
			memcpy(nfapi_rt_del_param6.dst_addr.w_addr,
			       nfapi_rt_entry6.dst_addr.w_addr,
			       sizeof(struct in6_addr));
			nfapi_rt_del_param6.tc = nfapi_rt_entry6.tc;
			nfapi_rt_del_param6.rt_table_id =
						     nfapi_rt_entry6.rt_table_id;
			ret = nf_ip6_fwd_route_delete(0, &nfapi_rt_del_param6,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &out_args6, NULL);
			if (!ret)
				printf("%s IPv6 route from RT table %d\n",
					nl_act_tostr(action),
					nfapi_rt_del_param6.rt_table_id);
		}

		if (!ret)
			/* route was just un-offloaded */
			nl_object_unmark(nl_obj);
		else if (ret != -ENOENT)
				error(0, -ret, "Failed to remove route");

		break;
	case NL_ACT_CHANGE:
		nl_object_dump(nl_obj, &dump_params);

		if (rt_family == AF_INET) {
			memcpy(&nfapi_rt_mod_param, &nfapi_rt_entry,
				sizeof(nfapi_rt_mod_param));
			ret = nf_ip4_fwd_route_modify(0, &nfapi_rt_mod_param,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &out_args, NULL);
			if (!ret)
				printf("%s IPv4 route from RT table %d\n",
					nl_act_tostr(action),
					nfapi_rt_entry.rt_table_id);
		} else {
			memcpy(&nfapi_rt_mod_param6, &nfapi_rt_entry6,
				sizeof(nfapi_rt_mod_param6));
			ret = nf_ip6_fwd_route_modify(0, &nfapi_rt_mod_param6,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &out_args6, NULL);
			if (!ret)
				printf("%s IPv6 route from RT table %d\n",
					nl_act_tostr(action),
					nfapi_rt_entry6.rt_table_id);
		}

		if (!ret)
			/* Mark the new route object as offloaded */
			nl_object_mark(nl_obj);
		else if (ret != -ENOENT)
			error(0, -ret, "Failed to update route");

		break;
	}
}

void rule_cache_change_cb(struct nl_cache *cache __maybe_unused,
			   struct nl_object *nl_obj,
			   int action,
			   void *arg __maybe_unused)
{
	struct rtnl_rule *rule = (struct rtnl_rule *)nl_obj;
	int rule_act;
	struct nf_ip4_fwd_pbr_rule nfapi_rule;
	struct nf_ip4_fwd_rule_outargs out_args;
	struct nf_ip6_fwd_pbr_rule nfapi_rule6;
	struct nf_ip6_fwd_pbr_rule_outargs out_args6;
	struct nf_ip4_fwd_pbr_rule_del nfapi_rule_params;
	struct nf_ip6_fwd_pbr_rule_del nfapi_rule_params6;
	int32_t ret;
	int family;

	/* whe handle only rule add/delete */
	if (action != NL_ACT_NEW &&
	    action != NL_ACT_DEL)
		return;

	/* we handle only rules pointing to route tables */
	rule_act = rtnl_rule_get_action(rule);
	if (rule_act != FR_ACT_TO_TBL)
		return;

	family = rtnl_rule_get_family(rule);
	if (family == AF_INET)
		ret = fill_nfapi_rule_params(rule, &nfapi_rule, family);
	else
		ret = fill_nfapi_rule_params(rule, &nfapi_rule6, family);

	if (ret < 0)
		return;



	nl_object_dump(nl_obj, &dump_params);

	if (action == NL_ACT_DEL) {
		/* rule is not offloaded */
		if (!nl_object_is_marked(nl_obj))
			return;

		if (family == AF_INET) {
			memcpy(&nfapi_rule_params, &nfapi_rule,
				sizeof(nfapi_rule_params));
			ret = nf_ip4_fwd_pbr_rule_delete(0, &nfapi_rule_params,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &out_args, NULL);
		} else {
			memcpy(&nfapi_rule_params6, &nfapi_rule6,
				sizeof(nfapi_rule_params6));
			ret = nf_ip6_fwd_pbr_rule_delete(0, &nfapi_rule_params6,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      &out_args6, NULL);
		}
	}

	if (action == NL_ACT_NEW) {
		/* run route filter for this table */
		if (family == AF_INET)
			run_route_filter(route_cache, &nfapi_rule, rule);
		else
			run_route_filter(route_cache, &nfapi_rule6, rule);
	}

}

static void *nl_events_loop(void *data __maybe_unused)
{
	struct sigaction new_action, old_action;
	int ret;

	quit = 0;
	new_action.sa_handler = nl_sig_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGUSR1, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN)
		sigaction(SIGUSR1, &new_action, NULL);

	dump_params.dp_fd = stdout;

	ret = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE,
				  &cache_mngr);
	if (ret < 0) {
		fprintf(stderr, "nl_cache_mngr_alloc failed %d\n", ret);
		goto out;
	}

	ret = nl_cache_mngr_add(cache_mngr, "route/route",
				route_cache_change_cb, NULL, &route_cache);
	if (ret < 0) {
		fprintf(stderr, "nl_cache_mngr_add route cache failed %d\n",
			ret);
		goto out1;
	}

	ret = nl_cache_mngr_add(cache_mngr, "route/neigh",
				neigh_cache_change_cb, route_cache,
				&neigh_cache);
	if (ret < 0) {
		fprintf(stderr, "nl_cache_mngr_add neigh cache failed %d\n",
			ret);
		goto out1;
	}

	ret = rtnl_route_read_table_names(RT_FILE_NAME);
	if (ret) {
		fprintf(stderr, "failed to read file %s\n", RT_FILE_NAME);
		goto out1;
	}
	rt_local = rtnl_route_str2table("local");

	while (!quit) {
		/* update caches */
		ret = nl_cache_mngr_poll(cache_mngr, 100);
		if (ret < 0 && ret != -NLE_INTR && ret != -NLE_AGAIN) {
			fprintf(stderr, "Polling failed: %s", nl_geterror(ret));
			break;
		}
	}

out1:
	nl_cache_mngr_free(cache_mngr);
out:
	pthread_exit(NULL);
}

int setup_nl_events_loop(void)
{
	int ret;

	ret = pthread_create(&tid, NULL, nl_events_loop, NULL);
	if (ret < 0)
		error(0, ret, "Failed to create NL EVENTS thread");

	return ret;
}

int teardown_nl_events_loop(void)
{
	int ret;

	quit = 1;

	ret = pthread_kill(tid, SIGUSR1);
	if (ret) {
		error(0, ret, "Failed to send signal to NL EVENTS thread");
		return ret;
	}

	ret = pthread_join(tid, NULL);
	if (ret)
		error(0, ret, "Failed to join the NL EVENTS thread");

	return ret;
}
