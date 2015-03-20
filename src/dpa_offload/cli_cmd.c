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

#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <nfinfra_nfapi.h>
#include <ip4_fwd_nfapi.h>
#include <ip6_fwd_nfapi.h>
#include <ipsec_nfapi.h>

#include "cli_cmd.h"
#include "xfrm_events.h"
#include "nf_init.h"
#ifdef ENABLE_TRACE
#include "fm_pcd_ext.h"
#include "fsl_dpa_ipsec.h"
#endif /* ENABLE_TRACE */

static int ipsec_stats(int argc, char *argv[]);
static int sa_stats(int argc, char *argv[]);
static int list_sa(int argc, char *argv[]);
static int rule_add(int argc, char *argv[]);
static int rule_get(int argc, char *argv[]);
static int rule_del(int argc, char *argv[]);
#ifdef ENABLE_TRACE
static int debug_ob_policy_miss_stats(int argc, char *argv[]);
static int debug_ob_policy_stats(int argc, char *argv[]);
static int debug_ib_policy_miss_stats(int argc, char *argv[]);
static int debug_ip4_route_miss_stats(int argc, char *argv[]);
static int debug_ip4_route_stats(int argc, char *argv[]);
static int debug_ip6_route_miss_stats(int argc, char *argv[]);
static int debug_ip6_route_stats(int argc, char *argv[]);
static int debug_ip4_rule_miss_stats(int argc, char *argv[]);
static int debug_ip4_rule_stats(int argc, char *argv[]);
static int debug_ip6_rule_miss_stats(int argc, char *argv[]);
static int debug_ip6_rule_stats(int argc, char *argv[]);
#endif /* ENABLE_TRACE */

const struct app_cli_command cli_command[MAX_CLI_COMMANDS] = {
	{ "ipsec_stats", ipsec_stats },
	{ "sa_stats", sa_stats },
	{ "list_sa", list_sa },
	{ "rule_add", rule_add },
	{ "rule_get", rule_get },
	{ "rule_del", rule_del },
#ifdef ENABLE_TRACE
	{ "debug_ob_policy_miss_stats", debug_ob_policy_miss_stats },
	{ "debug_ob_policy_stats", debug_ob_policy_stats },
	{ "debug_ib_policy_miss_stats", debug_ib_policy_miss_stats },
	{ "debug_ip4_route_miss_stats", debug_ip4_route_miss_stats },
	{ "debug_ip4_route_stats", debug_ip4_route_stats },
	{ "debug_ip6_route_miss_stats", debug_ip6_route_miss_stats },
	{ "debug_ip6_route_stats", debug_ip6_route_stats },
	{ "debug_ip4_rule_miss_stats", debug_ip4_rule_miss_stats },
	{ "debug_ip4_rule_stats", debug_ip4_rule_stats },
	{ "debug_ip6_rule_miss_stats", debug_ip6_rule_miss_stats },
	{ "debug_ip6_rule_stats", debug_ip6_rule_stats },
#else
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
	{ "", NULL },
#endif /* ENABLE_TRACE */
	{ "", NULL },
	{ "", NULL },
	{ "", NULL }
};

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

static int str_ton(int family, char *argv, void *sa)
{
	int ret;

	if (family == AF_INET)
		ret = inet_pton(family, argv,
				&(((struct sockaddr_in *)sa)->sin_addr));
	else
		ret = inet_pton(family, argv,
				&(((struct sockaddr_in6 *)sa)->sin6_addr));
	return ret;
}

static int ipsec_stats(int argc,
		char *argv[] __attribute__ ((unused)))
{
	struct nf_ipsec_global_stats_get_inargs in;
	struct nf_ipsec_global_stats_get_outargs out;
	int err;

	if (argc != 1)
		return -EINVAL;

	memset(&out, 0, sizeof(out));
	err = nf_ipsec_global_stats_get(0, &in, 0, &out, NULL);
	if (err == 0) {
		printf("\nIPSec global statistics:\n");
		printf("  OUTBOUND:\n");
		printf("    - received packets: %" PRIu64 "\n",
				out.stats.outb_received_pkts);
		printf("    - processed packets: %" PRIu64 "\n",
				out.stats.outb_processed_pkts);
		printf("  INBOUND:\n");
		printf("    - received packets: %" PRIu64 "\n",
				out.stats.inb_received_pkts);
		printf("    - processed packets: %" PRIu64 "\n",
				out.stats.inb_processed_pkts);
	} else
		fprintf(stderr, "Failed to acquire IPSec global statistics");

	return err;
}

static int sa_stats(int argc, char *argv[])
{
	struct list_head *l;
	struct nf_sa *sa = NULL;
	struct nf_ipsec_sa_get_inargs in;
	struct nf_ipsec_sa_get_outargs out;
	int id, seek, ret;

	if (argc < 2) {
		printf("\nSyntax: %s <sa_idx>\n\n", __func__);
		return -EINVAL;
	}

	seek = atoi(argv[1]);

	id = 0;
	list_for_each(l, &nf_sa_list) {
		if (id == seek) {
			sa = (struct nf_sa *)l;
			break;
		}
		id++;
	}
	if (!sa) {
		error(0, ENOENT, "SA #%d not found", seek);
		return -ENOENT;
	}
	printf("SA #%d parameters:\n", id);
	if (sa->dir == NF_IPSEC_INBOUND)
		printf("\tdir IN\n");
	else
		printf("\tdir OUT\n");
	dump_xfrm_sa_info(&sa->xfrm_sa_info);

	in.dir = sa->dir;
	in.operation = NF_IPSEC_SA_GET_EXACT;
	in.sa_id.spi = sa->spi;
	in.sa_id.dest_ip = sa->dest_ip;
	in.sa_id.protocol = sa->protocol;
	in.flags = NF_IPSEC_SA_GET_STATS;

	memset(&out, 0, sizeof(out));
	ret = nf_ipsec_sa_get(0, &in, 0, &out, NULL);
	if (ret)
		return ret;

	printf("SA #%d statistics:\n", id);
	printf("\tReceived:  %" PRIu64 " packets\n", out.stats.received_pkts);
	printf("\tProcessed: %" PRIu64 " packets (%" PRIu64 " bytes)\n\n",
		out.stats.processed_pkts, out.stats.processed_bytes);

	return 0;
}

static int list_sa(int argc __attribute__ ((unused)),
		char *argv[] __attribute__ ((unused)))
{
	struct list_head *l;
	struct nf_sa *nf_sa;
	unsigned idx = 0;

	printf("Showing configured SAs:\n");
	if (list_empty(&nf_sa_list)) {
		printf("\t--- none ---\n\n");
		return 0;
	}

	list_for_each(l, &nf_sa_list) {
		nf_sa = (struct nf_sa *)l;
		if (nf_sa->dir == NF_IPSEC_INBOUND)
			printf("%u)\tdir IN\n", idx++);
		else
			printf("%u)\tdir OUT\n", idx++);
		dump_xfrm_sa_info(&nf_sa->xfrm_sa_info);
	}
	printf("\n");

	return 0;
}

static int rule_add(int argc, char *argv[])
{
	if (argc < 6)
		return -EINVAL;

	if (!strcmp(argv[1], "ipv4")) {
		int ifid;
		struct nf_ip4_fwd_pbr_rule nfapi_rule;
		struct nf_ip4_fwd_rule_outargs out_args;
		int ret = 0;
		char *ch;
		struct sockaddr_in sa;

		memset(&nfapi_rule, 0 , sizeof(nfapi_rule));
		memset(&sa, 0, sizeof(sa));
		ch = strtok(argv[2], "/");
		str_ton(AF_INET, ch, &sa);
		nfapi_rule.src_addr = sa.sin_addr.s_addr;
		ch = strtok(NULL, "/");
		nfapi_rule.srcip_prefix = atoi(ch);
		ifid = if_nametoindex(argv[3]);
		if (ifid)
			nfapi_rule.in_ifid = ifid;
		else
			return -EINVAL;

		nfapi_rule.priority = atoi(argv[4]);
		if (argc > 6) {
			nfapi_rule.tos = strtol(argv[5],  NULL, 16);
			nfapi_rule.rt_table_no =  atoi(argv[6]);
		} else
			nfapi_rule.rt_table_no = atoi(argv[5]);
		ret = nf_ip4_fwd_pbr_rule_add(0, &nfapi_rule,
				   NF_API_CTRL_FLAG_NO_RESP_EXPECTED, &out_args,
				   NULL);
		if (ret) {
			printf("nf_ip4_fwd_pbr_rule_add. Error (%d)\n", ret);
			return -EINVAL;
		}

	} else if (!strcmp(argv[1], "ipv6")) {
		int ifid, ret = 0;
		struct nf_ip6_fwd_pbr_rule nfapi_rule;
		struct nf_ip6_fwd_pbr_rule_outargs out_args;
		char *ch;
		struct sockaddr_in6 sa;

		memset(&nfapi_rule, 0 , sizeof(nfapi_rule));
		memset(&sa, 0, sizeof(sa));
		ch = strtok(argv[2], "/");
		str_ton(AF_INET6, ch, &sa);
		memcpy(nfapi_rule.src_addr.w_addr,
			sa.sin6_addr.s6_addr,
			sizeof(struct in6_addr));
		ch = strtok(NULL, "/");
		nfapi_rule.srcip_prefix = atoi(ch);
		ifid = if_nametoindex(argv[3]);
		if (ifid)
			nfapi_rule.in_ifid = ifid;
		else
			return -EINVAL;

		nfapi_rule.priority = atoi(argv[4]);
		if (argc > 6) {
			nfapi_rule.tc = strtol(argv[5], NULL, 16);
			nfapi_rule.rt_table_no = atoi(argv[6]);
		} else
			nfapi_rule.rt_table_no = atoi(argv[5]);
		ret = nf_ip6_fwd_pbr_rule_add(0, &nfapi_rule,
				   NF_API_CTRL_FLAG_NO_RESP_EXPECTED, &out_args,
				   NULL);
		if (ret) {
			printf("nf_ip6_fwd_pbr_rule_add. Error (%d)\n", ret);
			return -EINVAL;
		}

	} else
		return -EINVAL;

	return 0;
}

static int rule_get(int argc, char *argv[])
{
	struct in_addr saddr_in;
	struct in6_addr saddr_in6;
	struct in_addr daddr_in;
	struct in6_addr daddr_in6;
	char dst[INET6_ADDRSTRLEN];
	char iif_name[6];
	const char *get_first = "get_first";
	const char *get_next = "get_next";
	const char *get_exact = "get_exact";
	int family;

	if (strcmp(argv[2], get_first) && (argc < 3))
		return -EINVAL;

	if (!strcmp(argv[1], "ipv4")) {
		int ret = 0;
		struct nf_ip4_fwd_pbr_rule_get_inargs inargs;
		struct nf_ip4_fwd_pbr_rule_get_outargs out;
		void *saddr, *daddr;

		family = AF_INET;
		memset(&inargs, 0,
				sizeof(struct nf_ip4_fwd_pbr_rule_get_inargs));
		memset(&out, 0,
				sizeof(struct nf_ip4_fwd_pbr_rule_get_outargs));
		if (!strcmp(argv[2], get_first))
			inargs.operation = NF_IP4_FWD_PBR_GET_FIRST;
		else if (!strcmp(argv[2], get_next))
			inargs.operation = NF_IP4_FWD_PBR_GET_NEXT;
		else if (!strcmp(argv[2], get_exact))
			inargs.operation = NF_IP4_FWD_PBR_GET_EXACT;
		else
			return -EINVAL;

		if (!strcmp(argv[2], get_first)) {
			if (argc != 3)
				return -EINVAL;

			goto get_rule_ipv4;
		}

		inargs.pbr_rule_params.priority = atoi(argv[3]);

get_rule_ipv4:
		ret = nf_ip4_fwd_pbr_get(0, &inargs,
				NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
				&out, NULL);
		if (!ret) {
			saddr_in.s_addr = out.pbr_rule_params.src_addr;
			daddr_in.s_addr = out.pbr_rule_params.dst_addr;
			saddr = &saddr_in.s_addr;
			daddr = &daddr_in.s_addr;
			printf("\npriority %d ",
				out.pbr_rule_params.priority);
			printf("saddr %s ", inet_ntop(family,
				saddr, dst, sizeof(dst)));
			printf("daddr %s ", inet_ntop(family,
				daddr, dst, sizeof(dst)));
			if (out.pbr_rule_params.tos)
				printf("tos 0x%x ", out.pbr_rule_params.tos);
			if_indextoname(out.pbr_rule_params.in_ifid, iif_name);
			printf("iif %s ", iif_name);
			printf("table %d\n\n", out.pbr_rule_params.rt_table_no);
		} else {
			printf("nf_ip4_fwd_pbr_get. Error (%d)\n", ret);
			return -EINVAL;
		}
	} else if (!strcmp(argv[1], "ipv6")) {
		int ret = 0;
		struct nf_ip6_fwd_pbr_rule_get_inargs inargs;
		struct nf_ip6_fwd_pbr_rule_get_outargs out;
		void *saddr, *daddr;

		family = AF_INET6;
		memset(&inargs, 0,
				sizeof(struct nf_ip6_fwd_pbr_rule_get_inargs));
		memset(&out, 0,
				sizeof(struct nf_ip6_fwd_pbr_rule_get_outargs));
		if (!strcmp(argv[2], get_first))
			inargs.operation = NF_IP6_FWD_PBR_GET_FIRST;
		else if (!strcmp(argv[2], get_next))
			inargs.operation = NF_IP6_FWD_PBR_GET_NEXT;
		else if (!strcmp(argv[2], get_exact))
			inargs.operation = NF_IP6_FWD_PBR_GET_EXACT;
		else
			return -EINVAL;

		if (!strcmp(argv[2], get_first)) {
			if (argc != 3)
				return -EINVAL;

			goto get_rule_ipv6;
		}

		inargs.pbr_rule_params.priority = atoi(argv[3]);

get_rule_ipv6:
		ret = nf_ip6_fwd_pbr_rule_get(0, &inargs,
				NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
				&out, NULL);

		if (!ret) {
			memcpy(&saddr_in6.s6_addr,
			       out.pbr_rule_params.src_addr.w_addr,
			       sizeof(saddr_in6.s6_addr));
			memcpy(daddr_in6.s6_addr,
			       out.pbr_rule_params.dst_addr.w_addr,
			       sizeof(daddr_in6.s6_addr));
			saddr = &saddr_in6.s6_addr;
			daddr = &daddr_in6.s6_addr;
			printf("\npriority %d ",
				out.pbr_rule_params.priority);
			printf("saddr %s ", inet_ntop(family,
				saddr, dst, sizeof(dst)));
			printf("daddr %s ", inet_ntop(family,
				daddr, dst, sizeof(dst)));
			if (out.pbr_rule_params.tc)
				printf("tos 0x%x ", out.pbr_rule_params.tc);
			if_indextoname(out.pbr_rule_params.in_ifid, iif_name);
			printf("iif %s ", iif_name);
			printf("table %d\n", out.pbr_rule_params.rt_table_no);
		} else {
			printf("nf_ip6_fwd_pbr_get. Error (%d)\n", ret);
			return -EINVAL;
		}

	}

	return 0;
}

static int rule_del(int argc, char *argv[])
{
	if (argc < 5)
		return -EINVAL;

	if (!strcmp(argv[1], "ipv4")) {
		struct nf_ip4_fwd_pbr_rule_del nfapi_rule;
		int ret = 0, ifid;
		char *ch;
		struct sockaddr_in sa;

		memset(&nfapi_rule, 0 , sizeof(nfapi_rule));
		memset(&sa, 0, sizeof(sa));

		ch = strtok(argv[2], "/");
		str_ton(AF_INET, ch, &sa);
		nfapi_rule.src_addr = sa.sin_addr.s_addr;
		ch = strtok(NULL, "/");
		nfapi_rule.srcip_prefix = atoi(ch);
		nfapi_rule.priority = atoi(argv[4]);
		ifid = if_nametoindex(argv[3]);
		if (ifid)
			nfapi_rule.in_ifid = ifid;
		else
			return -EINVAL;

		if (argc > 5)
			nfapi_rule.tos = strtol(argv[5], NULL, 16);

		ret = nf_ip4_fwd_pbr_rule_delete(0, &nfapi_rule,
					      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      NULL, NULL);
		if (ret) {
			printf("nf_ip4_fwd_pbr_rule_delete. Error (%d)\n", ret);
			return -EINVAL;
		}
	} else if (!strcmp(argv[1], "ipv6")) {
		int ifid, ret = 0;
		struct nf_ip6_fwd_pbr_rule_del nfapi_rule;
		char *ch;
		struct sockaddr_in6 sa;

		memset(&nfapi_rule, 0 , sizeof(nfapi_rule));
		memset(&sa, 0, sizeof(sa));

		ch = strtok(argv[2], "/");
		str_ton(AF_INET6, ch, &sa);
		memcpy(nfapi_rule.src_addr.w_addr, sa.sin6_addr.s6_addr,
			sizeof(struct in6_addr));
		ch = strtok(NULL, "/");
		nfapi_rule.srcip_prefix = atoi(ch);
		ifid = if_nametoindex(argv[3]);
		if (ifid)
			nfapi_rule.in_ifid = ifid;
		else
			return -EINVAL;

		nfapi_rule.priority = atoi(argv[4]);
		if (argc > 5)
			nfapi_rule.tc = strtol(argv[5], NULL, 16);
		ret = nf_ip6_fwd_pbr_rule_delete(0, &nfapi_rule,
				      	      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
					      NULL, NULL);
		if (ret) {
			printf("nf_ip6_fwd_pbr_rule_delete. Error (%d)\n", ret);
			return -EINVAL;
		}
	} else
		return -EINVAL;

	return 0;
}

#ifdef ENABLE_TRACE
static int dump_match_table_miss_stats(const t_Handle *ccnode, unsigned num)
{
	t_Error err;
	unsigned i;
	t_FmPcdCcKeyStatistics stats;
	int ret = 0;

	for (i = 0; i < num; i++)
	{
		if (!ccnode[i]) {
			printf("o %d) --- not initialized ---\n", i);
			continue;
		}

		printf("o %d) ccnode=0x%x\n", i, (unsigned)ccnode[i]);

		err = FM_PCD_MatchTableGetMissStatistics(
				ccnode[i],
				&stats);
		if (err != E_OK) {
			printf("\t- Miss : FAILED TO GET STATS\n");
			ret = -EINVAL;
		}

		printf("\t- Miss : %u frames\n", stats.frameCount);
	}

	return ret;
}

static int dump_hash_table_miss_stats(const t_Handle *ccnode, unsigned num)
{
	t_Error err;
	unsigned i;
	t_FmPcdCcKeyStatistics stats;
	int ret = 0;

	for (i = 0; i < num; i++)
	{
		if (!ccnode[i]) {
			printf("o %d) --- not initialized ---\n", i);
			continue;
		}

		printf("o %d) ccnode=0x%x\n", i, (unsigned)ccnode[i]);

		err = FM_PCD_HashTableGetMissStatistics(
				ccnode[i],
				&stats);
		if (err != E_OK) {
			printf("\t- Miss : FAILED TO GET STATS\n");
			ret = -EINVAL;
		}

		printf("\t- Miss : %u frames\n", stats.frameCount);
	}

	return ret;
}

static int dump_match_table_entry_stats(t_Handle ccnode, int entry_idx)
{
	t_Error err;
	t_FmPcdCcKeyStatistics stats;

	err = FM_PCD_MatchTableGetKeyStatistics(
		ccnode,
		entry_idx,
		&stats);
	if (err != E_OK) {
		printf("\t- entry #%d : FAILED TO GET STATS\n", entry_idx);
		return -EINVAL;
	}

	printf("\t- entry #%d : %u frames\n", entry_idx, stats.frameCount);

	return 0;
}

static int debug_ob_policy_miss_stats(int argc __attribute__ ((unused)),
		char *argv[] __attribute__ ((unused)))
{
	int ret = 0;

	printf("Dumping OUTBOUND (pre-SEC) policy table MISS statistics:\n");
	ret = dump_match_table_miss_stats(ob_pre_cc_node,
					DPA_IPSEC_MAX_SUPPORTED_PROTOS);
	printf("\n");

	return ret;
}

static int debug_ob_policy_stats(int argc, char *argv[])
{
	int table_idx;
	int entry_idx;
	int ret;

	if (argc < 3) {
		printf("\nSyntax: %s <table_idx> <entry_idx>\n\n", __func__);
		return -EINVAL;
	}

	table_idx = atoi(argv[1]);
	entry_idx = atoi(argv[2]);

	if ((table_idx < 0) || (table_idx >= DPA_IPSEC_MAX_SUPPORTED_PROTOS)) {
		printf("OUTBOUND (pre-SEC) policy table #%d is out of range. Only indexes in the range 0-%d are available.\n\n",
			table_idx, DPA_IPSEC_MAX_SUPPORTED_PROTOS - 1);
		return -EINVAL;
	}

	if (!ob_pre_cc_node[table_idx]) {
		printf("OUTBOUND (pre-SEC) policy table #%d:\n", table_idx);
		printf("\t--- table not initialized ---\n\n");
		return -ENXIO;
	}

	printf("OUTBOUND (pre-SEC) policy table #%d (ccnode=0x%x):\n",
		table_idx, (unsigned)ob_pre_cc_node[table_idx]);

	ret = dump_match_table_entry_stats(ob_pre_cc_node[table_idx],
					entry_idx);
	printf("\n");

	return ret;
}

static int debug_ib_policy_miss_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	int ret = 0;

	printf("Dumping INBOUND (pre-SEC) policy table MISS statistics:\n");
	ret = dump_hash_table_miss_stats(ib_pre_cc_node,
					DPA_IPSEC_MAX_SA_TYPE);
	printf("\n");

	return ret;
}

static int debug_ip4_route_miss_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	int ret = 0;

	printf("Dumping IPv4 route MISS statistics:\n");
	ret = dump_match_table_miss_stats(ip4_route_cc_node,
					IP4_ROUTE_TABLES);
	printf("\n");

	return ret;
}

static int debug_ip4_route_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	int table_idx;
	int entry_idx;
	int ret;

	if (argc < 3) {
		printf("\nSyntax: %s <table_idx> <entry_idx>\n\n", __func__);
		return -EINVAL;
	}

	table_idx = atoi(argv[1]);
	entry_idx = atoi(argv[2]);

	if ((table_idx < 0) || (table_idx >= IP4_ROUTE_TABLES)) {
		printf("IPv4 route table #%d is out of range. Only indexes in the range 0-%d are available.\n\n",
			table_idx, IP4_ROUTE_TABLES - 1);
		return -EINVAL;
	}

	printf("IPv4 route table #%d (ccnode=0x%x):\n",
		table_idx, (unsigned)ip4_route_cc_node[table_idx]);

	ret = dump_match_table_entry_stats(ip4_route_cc_node[table_idx],
					entry_idx);
	printf("\n");

	return ret;
}

static int debug_ip6_route_miss_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	int ret = 0;

	printf("Dumping IPv6 route MISS statistics:\n");
	ret = dump_match_table_miss_stats(ip6_route_cc_node,
					IP6_ROUTE_TABLES);
	printf("\n");

	return ret;
}

static int debug_ip6_route_stats(int argc, char *argv[])
{
	int table_idx;
	int entry_idx;
	int ret;

	if (argc < 3) {
		printf("\nSyntax: %s <table_idx> <entry_idx>\n\n", __func__);
		return -EINVAL;
	}

	table_idx = atoi(argv[1]);
	entry_idx = atoi(argv[2]);

	if ((table_idx < 0) || (table_idx >= IP6_ROUTE_TABLES)) {
		printf("IPv6 route table #%d is out of range. Only indexes in the range 0-%d are available.\n\n",
			table_idx, IP6_ROUTE_TABLES - 1);
		return -EINVAL;
	}

	printf("IPv6 route table #%d (ccnode=0x%x):\n",
		table_idx, (unsigned)ip6_route_cc_node[table_idx]);

	ret = dump_match_table_entry_stats(ip6_route_cc_node[table_idx],
					entry_idx);
	printf("\n");

	return ret;
}

static int debug_ip4_rule_miss_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	return -ENOTSUP;
}

static int debug_ip4_rule_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	return -ENOTSUP;
}

static int debug_ip6_rule_miss_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	return -ENOTSUP;
}

static int debug_ip6_rule_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	return -ENOTSUP;
}
#endif /* ENABLE_TRACE */
