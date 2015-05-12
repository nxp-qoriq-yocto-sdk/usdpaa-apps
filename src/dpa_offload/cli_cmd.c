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
#include "app_common.h"
#ifdef ENABLE_TRACE
#include "fm_pcd_ext.h"
#include "fsl_dpa_ipsec.h"
#endif /* ENABLE_TRACE */

static int ipsec_stats(int argc, char *argv[]);
static int sa_stats(int argc, char *argv[]);
static int list_sa(int argc, char *argv[]);
static int ib_rule_add4(int argc, char *argv[]);
static int ib_rule_add6(int argc, char *argv[]);
static int ib_rule_del4(int argc, char *argv[]);
static int ib_rule_del6(int argc, char *argv[]);
#ifdef ENABLE_TRACE
static int debug_ob_policy_miss_stats(int argc, char *argv[]);
static int debug_ob_policy_stats(int argc, char *argv[]);
static int debug_ib_policy_miss_stats(int argc, char *argv[]);
static int debug_ip4_route_miss_stats(int argc, char *argv[]);
static int debug_ip4_route_stats(int argc, char *argv[]);
static int debug_ip6_route_miss_stats(int argc, char *argv[]);
static int debug_ip6_route_stats(int argc, char *argv[]);
static int debug_ib_ip4_rule_miss_stats(int argc, char *argv[]);
static int debug_ib_ip4_rule_stats(int argc, char *argv[]);
static int debug_ib_ip6_rule_miss_stats(int argc, char *argv[]);
static int debug_ib_ip6_rule_stats(int argc, char *argv[]);
#endif /* ENABLE_TRACE */

const struct app_cli_command cli_command[MAX_CLI_COMMANDS] = {
	{ "ipsec_stats", ipsec_stats },
	{ "sa_stats", sa_stats },
	{ "list_sa", list_sa },
	{ "ib_rule_add4", ib_rule_add4 },
	{ "ib_rule_add6", ib_rule_add6 },
	{ "ib_rule_del4", ib_rule_del4 },
	{ "ib_rule_del6", ib_rule_del6 },
#ifdef ENABLE_TRACE
	{ "debug_ob_policy_miss_stats", debug_ob_policy_miss_stats },
	{ "debug_ob_policy_stats", debug_ob_policy_stats },
	{ "debug_ib_policy_miss_stats", debug_ib_policy_miss_stats },
	{ "debug_ip4_route_miss_stats", debug_ip4_route_miss_stats },
	{ "debug_ip4_route_stats", debug_ip4_route_stats },
	{ "debug_ip6_route_miss_stats", debug_ip6_route_miss_stats },
	{ "debug_ip6_route_stats", debug_ip6_route_stats },
	{ "debug_ib_ip4_rule_miss_stats", debug_ib_ip4_rule_miss_stats },
	{ "debug_ib_ip4_rule_stats", debug_ib_ip4_rule_stats },
	{ "debug_ib_ip6_rule_miss_stats", debug_ib_ip6_rule_miss_stats },
	{ "debug_ib_ip6_rule_stats", debug_ib_ip6_rule_stats },
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
		printf("    - encrypted packets: %" PRIu64 "\n",
				out.stats.outb_sec_applied_pkts);
		printf("    - encrypted bytes: %" PRIu64 "\n",
				out.stats.outb_sec_applied_bytes);
		printf("  INBOUND:\n");
		printf("    - received packets: %" PRIu64 "\n",
				out.stats.inb_received_pkts);
		printf("    - processed packets: %" PRIu64 "\n",
				out.stats.inb_processed_pkts);
		printf("    - decrypted packets: %" PRIu64 "\n",
				out.stats.inb_sec_applied_pkts);
		printf("    - decrypted bytes: %" PRIu64 "\n",
				out.stats.inb_sec_applied_bytes);
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

static void acquire_ip4_rule_params(char *argv[], struct nf_ip4_fwd_pbr_rule *ip4_rule)
{
	char *ch;
	struct sockaddr_in addr;

	/* Acquire source IPv4 address */
	memset(&addr, 0, sizeof(addr));
	ch = strtok(argv[1], "/");
	str_ton(AF_INET, ch, &addr);
	ip4_rule->src_addr = addr.sin_addr.s_addr;
	ch = strtok(NULL, "/");
	if (ch)
		ip4_rule->srcip_prefix = atoi(ch);
	else
		ip4_rule->srcip_prefix = DPA_OFFLD_IPv4_ADDR_LEN_BYTES * 8;

	/* Acquire destination IPv4 address */
	memset(&addr, 0, sizeof(addr));
	ch = strtok(argv[2], "/");
	str_ton(AF_INET, ch, &addr);
	ip4_rule->dst_addr = addr.sin_addr.s_addr;
	ch = strtok(NULL, "/");
	if (ch)
		ip4_rule->dstip_prefix = atoi(ch);
	else
		ip4_rule->dstip_prefix = DPA_OFFLD_IPv4_ADDR_LEN_BYTES * 8;
}

static void acquire_ip6_rule_params(char *argv[], struct nf_ip6_fwd_pbr_rule *ip6_rule)
{
	char *ch;
	struct sockaddr_in6 addr;

	/* Acquire source IPv6 address */
	memset(&addr, 0, sizeof(addr));
	ch = strtok(argv[1], "/");
	str_ton(AF_INET6, ch, &addr);
	memcpy(ip6_rule->src_addr.w_addr, addr.sin6_addr.s6_addr,
			sizeof(struct in6_addr));
	ch = strtok(NULL, "/");
	if (ch)
		ip6_rule->srcip_prefix = atoi(ch);
	else
		ip6_rule->srcip_prefix = DPA_OFFLD_IPv6_ADDR_LEN_BYTES * 8;

	/* Acquire destination IPv6 address */
	memset(&addr, 0, sizeof(addr));
	ch = strtok(argv[2], "/");
	str_ton(AF_INET6, ch, &addr);
	memcpy(ip6_rule->dst_addr.w_addr, addr.sin6_addr.s6_addr,
			sizeof(struct in6_addr));
	ch = strtok(NULL, "/");
	if (ch)
		ip6_rule->dstip_prefix = atoi(ch);
	else
		ip6_rule->dstip_prefix = DPA_OFFLD_IPv6_ADDR_LEN_BYTES * 8;
}

static int ib_rule_add4(int argc, char *argv[])
{
	struct nf_ip4_fwd_pbr_rule nfapi_rule;
	struct nf_ip4_fwd_rule_outargs out_args;
	int ret;

	if (argc < 5) {
		printf("\nSyntax: %s <src_ip>/<prefix> <dst_ip>/<prefix> <priority>\n\t\t<dest_route_table_no> [ <hex_tos> ]\n\n",
			__func__);
		return -EINVAL;
	}

	memset(&nfapi_rule, 0 , sizeof(struct nf_ip4_fwd_pbr_rule));

	if (ib_ifid) {
		nfapi_rule.in_ifid = ib_ifid;
		nfapi_rule.flags = NF_IP4_PBR_IN_IFACE_VALID;
	} else {
		error(0, EBADF, "Inbound interface Id is unknown at this time");
		return -EBADF;
	}

	acquire_ip4_rule_params(argv, &nfapi_rule);

	nfapi_rule.priority = atoi(argv[3]);

	nfapi_rule.rt_table_no = atoi(argv[4]);

	printf("\nAdding IPv4 inbound rule\n");
	TRACE("\t- Source: 0x%08x / %d\n", nfapi_rule.src_addr,
						nfapi_rule.srcip_prefix);
	TRACE("\t- Dest:   0x%08x / %d\n", nfapi_rule.dst_addr,
						nfapi_rule.dstip_prefix);
	TRACE("\t- Priority: %d\n", nfapi_rule.priority);
	TRACE("\t- Destination route table: %d\n", nfapi_rule.rt_table_no);

	if (argc > 5) {
		nfapi_rule.tos = strtol(argv[5], NULL, 16);
		TRACE("\t- TOS: 0x%x\n", nfapi_rule.tos);
#ifdef ENABLE_TRACE
	} else
		TRACE("\t- TOS: n/a\n");
#else
	}
#endif /* ENABLE_TRACE */

	ret = nf_ip4_fwd_pbr_rule_add(0, &nfapi_rule,
			   NF_API_CTRL_FLAG_NO_RESP_EXPECTED, &out_args,
			   NULL);
	if (ret) {
		error(0, -ret, "nf_ip4_fwd_pbr_rule_add returned");
		return ret;
	}

	printf("\nSuccess.\n");
	return 0;
}

static int ib_rule_add6(int argc, char *argv[])
{
	struct nf_ip6_fwd_pbr_rule nfapi_rule;
	struct nf_ip6_fwd_pbr_rule_outargs out_args;
	int ret;
#ifdef ENABLE_TRACE
	int i;
#endif /* ENABLE_TRACE */

	if (argc < 5) {
		printf("\nSyntax: %s <src_ip>/<prefix> <dst_ip>/<prefix> <priority>\n\t\t<dest_route_table_no> [ <hex_tos> ]\n\n",
			__func__);
		return -EINVAL;
	}

	memset(&nfapi_rule, 0 , sizeof(nfapi_rule));

	if (ib_ifid) {
		nfapi_rule.in_ifid = ib_ifid;
		nfapi_rule.flags = NF_IP6_PBR_IN_IFACE_VALID;
	} else {
		error(0, EBADF, "Inbound interface Id is unknown at this time");
		return -EBADF;
	}

	acquire_ip6_rule_params(argv, &nfapi_rule);

	nfapi_rule.priority = atoi(argv[3]);

	nfapi_rule.rt_table_no = atoi(argv[4]);

	printf("\nAdding IPv6 inbound rule\n");
#ifdef ENABLE_TRACE
	TRACE("\t- Source: ");
	for (i = 0; i < NF_IPV6_ADDRU32_LEN - 1; i++)
		TRACE("%04x:", nfapi_rule.src_addr.w_addr[i]);
	TRACE("%04x / %d\n", nfapi_rule.src_addr.w_addr[i],
						nfapi_rule.srcip_prefix);
	TRACE("\t- Dest: ");
	for (i = 0; i < NF_IPV6_ADDRU32_LEN - 1; i++)
		TRACE("%04x:", nfapi_rule.dst_addr.w_addr[i]);
	TRACE("%04x / %d\n", nfapi_rule.dst_addr.w_addr[i],
						nfapi_rule.dstip_prefix);
	TRACE("\t- Priority: %d\n", nfapi_rule.priority);
	TRACE("\t- Destination route table: %d\n", nfapi_rule.rt_table_no);
#endif /* ENABLE_TRACE */

	if (argc > 5) {
		nfapi_rule.tc = strtol(argv[5], NULL, 16);
		TRACE("\t- TC: 0x%x\n", nfapi_rule.tc);
#ifdef ENABLE_TRACE
	} else
		TRACE("\t- TC: n/a\n");
#else
	}
#endif /* ENABLE_TRACE */

	ret = nf_ip6_fwd_pbr_rule_add(0, &nfapi_rule,
			   NF_API_CTRL_FLAG_NO_RESP_EXPECTED, &out_args,
			   NULL);
	if (ret) {
		error(0, -ret, "nf_ip6_fwd_pbr_rule_add returned");
		return ret;
	}

	printf("\nSuccess.\n");
	return 0;
}

static int ib_rule_del4(int argc, char *argv[])
{
	struct nf_ip4_fwd_pbr_rule_del nfapi_rule_del;
	int ret;

	if (argc < 4) {
		printf("\nSyntax: %s <src_ip>/<prefix> <dst_ip>/<prefix> <priority> [ <hex_tos> ]\n\n",
			__func__);
		return -EINVAL;
	}

	memset(&nfapi_rule_del, 0 , sizeof(struct nf_ip4_fwd_pbr_rule_del));

	if (ib_ifid) {
		nfapi_rule_del.in_ifid = ib_ifid;
		nfapi_rule_del.flags = NF_IP4_PBR_IN_IFACE_VALID;
	} else {
		error(0, EBADF, "Inbound interface Id is unknown at this time");
		return -EBADF;
	}

	acquire_ip4_rule_params(argv, (struct nf_ip4_fwd_pbr_rule*)&nfapi_rule_del);

	nfapi_rule_del.priority = atoi(argv[3]);

	printf("\nRemove IPv4 inbound rule\n");
	TRACE("\t- Source: 0x%08x / %d\n", nfapi_rule_del.src_addr,
						nfapi_rule_del.srcip_prefix);
	TRACE("\t- Dest:   0x%08x / %d\n", nfapi_rule_del.dst_addr,
						nfapi_rule_del.dstip_prefix);
	TRACE("\t- Priority: %d\n", nfapi_rule_del.priority);

	if (argc > 4) {
		nfapi_rule_del.tos = strtol(argv[4], NULL, 16);
		TRACE("\t- TOS: 0x%x\n", nfapi_rule_del.tos);
#ifdef ENABLE_TRACE
	} else
		TRACE("\t- TOS: n/a\n");
#else
	}
#endif /* ENABLE_TRACE */

	ret = nf_ip4_fwd_pbr_rule_delete(0, &nfapi_rule_del,
				      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
				      NULL, NULL);
	if (ret) {
		error(0, -ret, "nf_ip4_fwd_pbr_rule_delete returned");
		return -EINVAL;
	}

	printf("\nSuccess.\n");
	return 0;
}

static int ib_rule_del6(int argc, char *argv[])
{
	struct nf_ip6_fwd_pbr_rule_del nfapi_rule_del;
	int ret;
#ifdef ENABLE_TRACE
	int i;
#endif /* ENABLE_TRACE */

	if (argc < 4) {
		printf("\nSyntax: %s <src_ip>/<prefix> <dst_ip>/<prefix> <priority> [ <hex_tc> ]\n\n",
			__func__);
		return -EINVAL;
	}

	memset(&nfapi_rule_del, 0 , sizeof(struct nf_ip6_fwd_pbr_rule_del));

	if (ib_ifid) {
		nfapi_rule_del.in_ifid = ib_ifid;
		nfapi_rule_del.flags = NF_IP6_PBR_IN_IFACE_VALID;
	} else {
		error(0, EBADF, "Inbound interface Id is unknown at this time");
		return -EBADF;
	}

	acquire_ip6_rule_params(argv, (struct nf_ip6_fwd_pbr_rule*)&nfapi_rule_del);

	nfapi_rule_del.priority = atoi(argv[3]);

	printf("\nRemove IPv6 inbound rule\n");
#ifdef ENABLE_TRACE
	TRACE("\t- Source: ");
	for (i = 0; i < NF_IPV6_ADDRU32_LEN - 1; i++)
		TRACE("%04x:", nfapi_rule_del.src_addr.w_addr[i]);
	TRACE("%04x / %d\n", nfapi_rule_del.src_addr.w_addr[i],
						nfapi_rule_del.srcip_prefix);
	TRACE("\t- Dest: ");
	for (i = 0; i < NF_IPV6_ADDRU32_LEN - 1; i++)
		TRACE("%04x:", nfapi_rule_del.dst_addr.w_addr[i]);
	TRACE("%04x / %d\n", nfapi_rule_del.dst_addr.w_addr[i],
						nfapi_rule_del.dstip_prefix);
	TRACE("\t- Priority: %d\n", nfapi_rule_del.priority);
#endif /* ENABLE_TRACE */

	if (argc > 4) {
		nfapi_rule_del.tc = strtol(argv[4], NULL, 16);
		TRACE("\t- TC: 0x%x\n", nfapi_rule_del.tc);
#ifdef ENABLE_TRACE
	} else
		TRACE("\t- TC: n/a\n");
#else
	}
#endif /* ENABLE_TRACE */

	ret = nf_ip6_fwd_pbr_rule_delete(0, &nfapi_rule_del,
				      NF_API_CTRL_FLAG_NO_RESP_EXPECTED,
				      NULL, NULL);
	if (ret) {
		error(0, -ret, "nf_ip6_fwd_pbr_rule_delete returned");
		return -EINVAL;
	}

	printf("\nSuccess.\n");
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
		printf("\nSyntax: %s <ip4_route_table_idx> <route_entry_idx>\n\n", __func__);
		printf("Note: ip4_route_table_idx should be in the range 0 - %d.\n",
			IP4_ROUTE_TABLES - 1);
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
		printf("\nSyntax: %s <ip6_route_table_idx> <entry_idx>\n\n", __func__);
		printf("Note: ip6_route_table_idx should be in the range 0 - %d.\n",
			IP6_ROUTE_TABLES - 1);
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

static int debug_ib_ip4_rule_miss_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	int ret = 0;

	printf("Dumping IPv4 rule MISS statistics:\n");
	ret = dump_match_table_miss_stats(ip4_rule_cc_node,
					IP4_RULE_TABLES);
	printf("\n");

	return ret;
}

static int debug_ib_ip4_rule_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	int table_idx;
	int entry_idx;
	int ret;

	if (argc < 3) {
		printf("\nSyntax: %s <ip4_rule_table_idx> <entry_idx>\n\n", __func__);
		printf("Note: ip4_rule_table_idx should be in the range 0 - %d.\n",
			IP4_RULE_TABLES - 1);
		return -EINVAL;
	}

	table_idx = atoi(argv[1]);
	entry_idx = atoi(argv[2]);

	if ((table_idx < 0) || (table_idx >= IP4_RULE_TABLES)) {
		printf("IPv4 rule table #%d is out of range. Only indexes in the range 0-%d are available.\n\n",
			table_idx, IP4_RULE_TABLES - 1);
		return -EINVAL;
	}

	printf("IPv4 rule table #%d (ccnode=0x%x):\n",
		table_idx, (unsigned)ip4_rule_cc_node[table_idx]);

	ret = dump_match_table_entry_stats(ip4_rule_cc_node[table_idx],
					entry_idx);
	printf("\n");

	return ret;
}

static int debug_ib_ip6_rule_miss_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	int ret = 0;

	printf("Dumping IPv6 rule MISS statistics:\n");
	ret = dump_match_table_miss_stats(ip6_rule_cc_node,
					IP6_RULE_TABLES);
	printf("\n");

	return ret;
}

static int debug_ib_ip6_rule_stats(int argc __attribute__ ((unused)),
			char *argv[] __attribute__ ((unused)))
{
	int table_idx;
	int entry_idx;
	int ret;

	if (argc < 3) {
		printf("\nSyntax: %s <ip6_rule_table_idx> <entry_idx>\n\n", __func__);
		printf("Note: ip6_rule_table_idx should be in the range 0 - %d.\n",
			IP6_RULE_TABLES - 1);
		return -EINVAL;
	}

	table_idx = atoi(argv[1]);
	entry_idx = atoi(argv[2]);

	if ((table_idx < 0) || (table_idx >= IP6_RULE_TABLES)) {
		printf("IPv6 rule table #%d is out of range. Only indexes in the range 0-%d are available.\n\n",
			table_idx, IP6_RULE_TABLES - 1);
		return -EINVAL;
	}

	printf("IPv6 rule table #%d (ccnode=0x%x):\n",
		table_idx, (unsigned)ip6_rule_cc_node[table_idx]);

	ret = dump_match_table_entry_stats(ip6_rule_cc_node[table_idx],
					entry_idx);
	printf("\n");

	return ret;
}
#endif /* ENABLE_TRACE */
