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

#include <ctype.h>
#include <error.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <flib/rta.h>
#include <libxml/parser.h>

#include <compat.h>
#include <dma_mem.h>
#include <fman.h>
#include <fsl_bman.h>
#include <fsl_qman.h>
#include <fsl_usd.h>
#include <of.h>
#include <sec.h>
#include <mem_cache.h>

#include "app_common.h"
#include "fsl_dpa_classifier.h"
#include "nf_init.h"
#include "init_nfapi.h"

/*************************** GLOBAL DATA ***************************/

/* How many bytes from the start of the frame to dump during debug: */
#define FRAME_CONTENT_DEBUG_DUMP_LEN	256

/* initialization data computed and used during the init sequence */
static struct app_init_data init;
struct nf_init_data *gbl_init = NULL;

#ifdef ENABLE_TRACE
t_Handle ob_pre_cc_node[DPA_IPSEC_MAX_SUPPORTED_PROTOS];
t_Handle ib_pre_cc_node[DPA_IPSEC_MAX_SA_TYPE];
t_Handle ip4_route_cc_node[IP4_ROUTE_TABLES];
t_Handle ip6_route_cc_node[IP6_ROUTE_TABLES];
#endif /* ENABLE_TRACE */

/* XML Configs & netcfg */
static const char __POL_PATH[] = __stringify(DEF_POL_PATH);
static const char __CFG_PATH[] = __stringify(DEF_CFG_PATH);
static const char __PCD_PATH[] = __stringify(DEF_PCD_PATH);
static const char __PDL_PATH[] = __stringify(DEF_PDL_PATH);
static const char __SWP_PATH[] = __stringify(DEF_SWP_PATH);
static const char *CFG_PATH = __CFG_PATH;
static const char *POL_PATH = __POL_PATH;
static const char *PCD_PATH = __PCD_PATH;
static const char *PDL_PATH = __PDL_PATH;
static const char *SWP_PATH = __SWP_PATH;

/* The forwarding logic uses a per-cpu FQ object for handling enqueues (and
 * ERNs), irrespective of the destination FQID. In this way, cache-locality is
 * more assured, and any ERNs that do occur will show up on the same CPUs they
 * were enqueued from. This works because ERN messages contain the FQID of the
 * original enqueue operation, so in principle any demux that's required by the
 * ERN callback can be based on that. Ie. the FQID set within "local_fq" is from
 * whatever the last executed enqueue was, the ERN handler can ignore it. */
static __thread struct qman_fq local_fq;

/* IPSEC Classifications labels */

/* Names used by FMC to identify fman ports. */
static const char *type_desc[] = { "OFFLINE", "MAC", "MAC" };

/* Names used by the application to identify INBOUND CC nodes used by IPSec. */
static const char * const ib_cc_labels[DPA_IPSEC_MAX_SA_TYPE] = {
	"ib_ipv4_esp_cc",		/* SA ipv4 */
	"ib_ipv4_esp_udp_cc",		/* SA ipv4 natt */
	"ib_ipv6_esp_cc",		/* SA ipv6 */
};

/* Names used by the application to identify OUTBOUND CC nodes used by IPSec. */
static const char * const ob_cc_labels[DPA_IPSEC_MAX_SUPPORTED_PROTOS] ={
	"ob_pre_ipv4_cc",		/* TCP ipv4 */
	"ob_pre_ipv6_cc",		/* TCP ipv6 */
	"ob_pre_ipv4_cc",		/* UDP ipv4 */
	"ob_pre_ipv6_cc",		/* UDP ipv6 */
	"ob_pre_ipv4_icmp_cc",		/* ICMP ipv4 */
	"ob_pre_ipv6_icmp_cc",		/* ICMP ipv6 */
	"ob_pre_ipv4_cc",		/* SCTP ipv4 */
	"ob_pre_ipv6_cc",		/* SCTP ipv6 */
	"ob_pre_ipv4_cc",		/* any ipv4 */
	"ob_pre_ipv6_cc",		/* any ipv6 */
};

/* Names used by application to identify OUTBOUND RX distributions used by
 * IPSec. */
const char * const ob_rx_dists[] = {
	"ob_rx_udp_dist",
	"ob_rx_tcp_dist",
	"ob_rx_ipv4_dist",
	"ob_rx_ipv6_dist"
};

/* Names used by the application to identify ROUTE Cc nodes used by IPFwd. */
const char * ip4_route_cc_labels[] = {
	"ob_post_ipv4_route_cc",
	"ib_post_ipv4_route_cc",
	""
};
const char * ip6_route_cc_labels[] = {
	"ob_post_ipv6_route_cc",
	"ib_post_ipv6_route_cc",
	""
};

/* Names used by the application to identify RULE Cc nodes used by IPFwd. */
const char * ip4_rule_cc_labels[] = {
	"ib_ipv4_rule_cc",
	""
};
const char * ip6_rule_cc_labels[] = {
	"ib_ipv6_rule_cc",
	""
};

struct cc_info {
	t_Handle handle;
	int num_keys;
	int key_size;
	struct fman_if *port;
};

static struct cc_info *ip4_route_cc_info	= NULL;
static int ip4_route_tables			= 0;
static struct cc_info *ip4_rule_cc_info		= NULL;
static int ip4_rule_tables			= 0;
static struct cc_info *ip6_route_cc_info	= NULL;
static int ip6_route_tables			= 0;
static struct cc_info *ip6_rule_cc_info		= NULL;
static int ip6_rule_tables			= 0;

/*
 * Names used by library to identify INBOUND policy verification
 * CC node used by IPSec.
 */
const char * const ib_policy_verification_cc_label = "flow_id_cc";

/*************************** FUNCTIONS ***************************/

/* getter funcs - to simplify access to the init data */
static inline struct fman_if *get_ipsec_if(enum nf_ipsec_port_role role)
{
	return (role >= 0 && role < MAX_PORTS) ?
			init.nfapi_init_data.ipsec.ifs_by_role[role] : NULL;
}

/* XML config parsing */
static inline int is_node(xmlNodePtr node, xmlChar *name)
{
	return xmlStrcmp(node->name, name) ? 0 : 1;
}

static void *get_attributes(xmlNodePtr node, xmlChar *attr)
{
	char *atr = (char *)xmlGetProp(node, attr);
	if (unlikely(atr == NULL))
		fprintf(stderr, "%s:%hu:%s() error: xmlGetProp(%s) not found\n",
				__FILE__, __LINE__, __func__,  attr);
	return atr;
}

static int parse_ipsec_config(const char *cfg_path)
{
	int p_idx, fm, i;
	enum fman_mac_type p_type;
	char * tmp;
	void * _if = NULL;
	xmlNodePtr node;
	xmlDocPtr doc;
	struct fm_eth_port_cfg *cfg = NULL;

	xmlInitParser();
	LIBXML_TEST_VERSION;
	xmlKeepBlanksDefault(0);

	/* Parse config file and get the root element. */
	doc = xmlParseFile(cfg_path);
	if (unlikely(doc == NULL)) {
		fprintf(stderr, "%s:%hu:%s() error: xmlParseFile(%s)\n",
				__FILE__, __LINE__, __func__, cfg_path);
		return -EINVAL;
	}

	node = xmlDocGetRootElement(doc);

	/*
	 * The XML has already been validated by the netcfg layer
	 * go directly to the engine node - process only the first one.
	 */
	while (node) {
		if (!xmlStrcmp(node->name, (const xmlChar *)CFG_FMAN_NODE))
			break;
		node = node->xmlChildrenNode;
	}

	/* Save the fman index. */
	tmp = (char *)get_attributes(node, BAD_CAST CFG_FMAN_NA_name);
	if (unlikely(!tmp) || unlikely(strncmp(tmp, "fm", 2)) ||
				unlikely(!isdigit(tmp[2]))) {
		fprintf(stderr, "%s:%hu:%s() error: attrtibute name in %s node"
				"is neither <fm0> nor <fm1> in XMLFILE(%s)\n",
				__FILE__, __LINE__, __func__,
				CFG_FMAN_NODE, cfg_path);
		return -EINVAL;
	}

	fm = tmp[2] - '0';
	init.fm_idx = fm;

	/* Save the ports info. */
	node = node->xmlChildrenNode;
	for (; unlikely(node != NULL); node = node->next) {

		if (unlikely(!is_node(node, BAD_CAST CFG_PORT_NODE)))
			continue;

		/* Get the MAC port number and policy name. */
		tmp = (char *)get_attributes(node, BAD_CAST CFG_PORT_NA_number);
		if (unlikely(tmp == NULL))
			break;
		p_idx = strtoul(tmp, NULL, 0);

		/* Get the MAC port type from PORT node attribute "type". */
		tmp = (char *)get_attributes(node, BAD_CAST CFG_PORT_NA_type);
		if (unlikely(tmp == NULL))
			break;
		p_type = (strcmp(tmp, "OFFLINE") == 0) ? fman_offline :
				 (strcmp(tmp,"10G") == 0) ? fman_mac_10g :
				 (strcmp(tmp,"ONIC") == 0) ? fman_onic :
				 fman_mac_1g;

		tmp = (char *)get_attributes(node, BAD_CAST CFG_PORT_NA_policy);
		if (unlikely(tmp == NULL))
			break;

		/* Get the corresponding fman_if handle for p_idx and p_type. */
		for (i = 0; i < init.nfapi_init_data.netcfg->num_ethports; i++) {
			cfg = &init.nfapi_init_data.netcfg->port_cfg[i];
			if ((fm == cfg->fman_if->fman_idx) &&
			    (p_type == cfg->fman_if->mac_type) &&
			    (p_idx == cfg->fman_if->mac_idx))
				_if = cfg->fman_if;
		}

		if (!_if) {
			fprintf(stderr, "Error: invalid interface (idx: %d type: %d)\n",
					p_idx, p_type);
			return -1;
		}

		/* save the fman_if as per its role (policy name) */

		if (!strcmp(tmp, CFG_OB_POLICY))
			init.nfapi_init_data.ipsec.ifs_by_role[OB] = _if;
		else if (!strcmp(tmp, CFG_IB_POLICY))
			init.nfapi_init_data.ipsec.ifs_by_role[IB] = _if;
		else if (!strcmp(tmp, CFG_IB_OH_POLICY))
			init.nfapi_init_data.ipsec.ifs_by_role[IB_OH] = _if;
		else if (!strcmp(tmp, CFG_OB_OH_PRE_POLICY))
			init.nfapi_init_data.ipsec.ifs_by_role[OB_OH_PRE] = _if;
		else if (!strcmp(tmp, CFG_OB_OH_POST_POLICY))
			init.nfapi_init_data.ipsec.ifs_by_role[OB_OH_POST] = _if;
		else
			fprintf(stderr, "Warning: interface found, but not used "
					"(idx: %d, type %d)\n", p_idx, p_type);
	}
	/* XXX: Check if all the interfaces have been found. */

	return 0;
}

static inline int reconfigure_tables(void)
{
	struct dpa_ipsec_pre_sec_out_params *pre_sec_out = NULL;
	struct dpa_ipsec_pol_table *any_ipv4_table, *any_ipv6_table;
	int i;

	/*
	 * reconfigure the array of outbound policy table parameters, in order
	 * to simplify the process of choosing the correct table during runtime
	 * add / remove policies operations
	 */
	pre_sec_out = &gbl_init->ipsec.ipsec_params.pre_sec_out_params;
	/* get the desc for the ANY tables */
	any_ipv4_table = &pre_sec_out->table[DPA_IPSEC_PROTO_ANY_IPV4];
	any_ipv6_table = &pre_sec_out->table[DPA_IPSEC_PROTO_ANY_IPV6];

	if (any_ipv4_table->dpa_cls_td == DPA_OFFLD_DESC_NONE ||
	    any_ipv6_table->dpa_cls_td == DPA_OFFLD_DESC_NONE) {
		error(0, EINVAL, "Outbound policy table for ANY Layer 4 protocol cannot be NULL\n");
		return -EINVAL;
	}

	/*
	 * replace the parameters of a table for a specific protocol, if an
	 * invalid table desc was provided, with those of the corresponding ANY
	 * table for that IP version
	 */
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS - 2; i++) {
		if (pre_sec_out->table[i].dpa_cls_td == DPA_OFFLD_DESC_NONE) {
			/* IPV4 table desc are at even indexes (IPV6 at odd) */
			if (i & 0x01)
				pre_sec_out->table[i] = *any_ipv6_table;
			else
				pre_sec_out->table[i] = *any_ipv4_table;
		}
	}

	return 0;
}

static int ipfwd_init_tables(const struct cc_info *cc_info,
			     struct nf_ipfwd_resources **res,
			     int num_tables)
{
	int i, j, ret, _td;
	struct dpa_cls_tbl_params cls_tbl_params;
	char *ifname;
	*res = malloc(sizeof(**res) +
			num_tables * sizeof(struct nf_ipfwd_cc));
	if (!res)
		return -ENOMEM;

	for (i = 0; i < num_tables; i++) {
		memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
		cls_tbl_params.cc_node = cc_info[i].handle;
		cls_tbl_params.type = DPA_CLS_TBL_EXACT_MATCH;
		cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_KEY;
		cls_tbl_params.exact_match_params.entries_cnt =
							cc_info[i].num_keys;
		cls_tbl_params.exact_match_params.key_size =
							cc_info[i].key_size;
		ret = dpa_classif_table_create(&cls_tbl_params, &_td);
		if (ret < 0)
			goto err;

		memset(&(*res)->nf_cc[i], 0, sizeof(struct nf_ipfwd_cc ));
		if (cc_info[i].port->mac_type == fman_offline) {
			/* This looks like a routing table: */
			(*res)->nf_cc[i].td = _td;
			(*res)->nf_cc[i].action.type = DPA_CLS_TBL_ACTION_ENQ;
			(*res)->nf_cc[i].rt_table_no = _td;
			printf("\t- td=rt_table_no=%d ... ccnode=0x%x\n", _td, (unsigned)cc_info[i].handle);
			continue;
		}

		ifname = cc_info[i].port->shared_mac_info.shared_mac_name;
		(*res)->nf_cc[i].ifid = if_nametoindex(ifname);

		printf("\t- td=%d, ccnode=0x%x, ifname=%s\n", _td, (unsigned)cc_info[i].handle, ifname);
	}

	(*res)->num_td = num_tables;
	(*res)->keysize = cc_info[i-1].key_size;

	return 0;

err:
	for (j = 0; j < i; j++) {
		_td = (*res)->nf_cc[j].td;
		dpa_classif_table_free(_td);
	}
	free(*res);

	return ret;
}

struct cc_info *get_ipfwd_cc_info(const char **labels,
		const struct fmc_model_t *_model, int *ccnodes_count)
{
	int i = 0, count = 0;
	unsigned j, p, m;
	struct cc_info *ccinfo;

	*ccnodes_count = 0;

	/* Count the number of identified Cc nodes */
	while (labels[i][0]) {
		for (j = 0; j < _model->ccnode_count; j++) {
			if (strstr(_model->ccnode_name[j], labels[i])) {
				(*ccnodes_count)++;
				break;
			}
		}
		i++;
	}

	if (!*ccnodes_count) {
		/* Didn't find anything. Nothing to do */
		return NULL;
	}

	ccinfo = malloc((*ccnodes_count) * sizeof(*ccinfo));
	if (!ccinfo)
		return NULL;

	i = 0;
	/* Fill in the information related to each Cc node: */
	while (labels[i][0]) {
		for (j = 0; j < _model->ccnode_count; j++) {
			if (strstr(_model->ccnode_name[j], labels[i])) {
				char ccnode_name[FMC_NAME_LEN];
				struct net_if *net_if;
				const struct fm_eth_port_cfg *port_cfg;
				char *sfm, *sport_type, *sport;
				unsigned fmc_engine, fmcport;
				unsigned fm_idx, mac_idx;
				enum fman_mac_type mac_type;
				bool offline_port;

				ccinfo[count].handle = _model->ccnode_handle[j];
				ccinfo[count].num_keys = _model->ccnode[j].keysParams.maxNumOfKeys;
				ccinfo[count].key_size = _model->ccnode[j].keysParams.keySize;
				ccinfo[count].port = NULL;
				printf("\t%d) \"%s\" ... cc_node=0x%x\n", count, labels[i], (unsigned)ccinfo[count].handle);

				/* Determine the port which owns this Cc node from the fmc model: */
				memcpy(ccnode_name, _model->ccnode_name[j], FMC_NAME_LEN);
				sfm = strtok(ccnode_name, "/");
				strtok(NULL, "/");
				sport_type = strtok(NULL, "/");
				if (strcasecmp(sport_type, "OFFLINE") == 0)
					offline_port = true;
				else
					offline_port = false;
				sport = strtok(NULL, "/");
				fmc_engine = atoi(&sfm[2]);
				fmcport = atoi(sport);

				/* Find the port information: */
				m = 0;
				while ((_model->fman[m].number != fmc_engine) && (m < _model->fman_count))
					m++;
				if (m >= _model->fman_count) {
					error(0, EINVAL, "No interface for \"%s\". (Could not find FMan engine #%u in fmc model)",
						_model->ccnode_name[j],
						fmc_engine);
					continue;
				}
				fm_idx = _model->fman[m].number;
				mac_idx = fmcport;

				p = 0;
				while (p < _model->fman[m].port_count) {
					if (_model->port[_model->fman[m].ports[p]].number == fmcport) {
						if ((offline_port) && (_model->port[_model->fman[m].ports[p]].type == e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
							break;
						if ((!offline_port) && (_model->port[_model->fman[m].ports[p]].type != e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
							break;
					}
					p++;
				}
				if (p >= _model->fman[m].port_count) {
					error(0, EINVAL, "No interface for \"%s\". (Cound not find port%u@fman%u in fmc model)",
						_model->ccnode_name[j],
						fmcport, fm_idx);
					continue;
				}

				switch (_model->port[_model->fman[m].ports[p]].type) {
				case e_FM_PORT_TYPE_RX_10G:
				case e_FM_PORT_TYPE_TX_10G:
					mac_type = fman_mac_10g;
					break;
				case e_FM_PORT_TYPE_RX:
				case e_FM_PORT_TYPE_TX:
					mac_type = fman_mac_1g;
					break;
				case e_FM_PORT_TYPE_OH_OFFLINE_PARSING:
					mac_type = fman_offline;
					break;
				default:
					error(0, EINVAL, "No interface for \"%s\". (Unrecognized port type (%d) for port%u@fman%u in fmc model)",
						_model->ccnode_name[j],
						_model->port[_model->fman[m].ports[p]].type,
						mac_idx, fm_idx);
					continue;
				}

				/* Find the NF interface that matches this port. */
				list_for_each_entry(net_if, &init.nfapi_init_data.ifs, node) {
					port_cfg = net_if->cfg;
					if ((port_cfg->fman_if->fman_idx == fm_idx) &&
						(port_cfg->fman_if->mac_idx == mac_idx) &&
						(port_cfg->fman_if->mac_type == mac_type)) {
							ccinfo[count].port = port_cfg->fman_if;
							break;
						}
				}
				if (!ccinfo[count++].port) {
					error (0, EINVAL, "No interface for \"%s\". (Cannot find USDPAA interface for port%u@fman%u of type %d)",
						_model->ccnode_name[j], mac_idx, fm_idx, mac_type);
					break;
				}

				break;
			}
		}
		if (count >= *ccnodes_count)
			break;
		i++;
	}

	return ccinfo;
}

static int ipfwd_acquire_cc_info(struct fmc_model_t *_cmodel)
{
	int ret = 0;

	printf("Identifying IPv4 routing tables\n");
	ip4_route_cc_info = get_ipfwd_cc_info(ip4_route_cc_labels, _cmodel,
							&ip4_route_tables);
	if (!ip4_route_cc_info) {
		ret = -EINVAL;
		goto acquire_cc_info_err;
	}
	printf("%d tables.\n", ip4_route_tables);

	printf("Identifying IPv4 rule tables\n");
	ip4_rule_cc_info = get_ipfwd_cc_info(ip4_rule_cc_labels, _cmodel,
							&ip4_rule_tables);
	if (!ip4_rule_cc_info) {
		ret = -EINVAL;
		goto acquire_cc_info_err;
	}
	printf("%d tables.\n", ip4_rule_tables);

	printf("Identifying IPv6 routing tables\n");
	ip6_route_cc_info = get_ipfwd_cc_info(ip6_route_cc_labels, _cmodel,
							&ip6_route_tables);
	if (!ip6_route_cc_info) {
		ret = -EINVAL;
		goto acquire_cc_info_err;
	}
	printf("%d tables.\n", ip6_route_tables);

	printf("Identifying IPv6 rule tables\n");
	ip6_rule_cc_info = get_ipfwd_cc_info(ip6_rule_cc_labels, _cmodel,
							&ip6_rule_tables);
	if (!ip6_rule_cc_info) {
		ret = -EINVAL;
		goto acquire_cc_info_err;
	}
	printf("%d tables.\n", ip6_rule_tables);

	return 0;

acquire_cc_info_err:
	free(ip4_rule_cc_info);
	ip4_rule_cc_info = NULL;
	ip4_rule_tables = 0;
	free(ip4_route_cc_info);
	ip4_route_cc_info = NULL;
	ip4_route_tables = 0;
	free(ip6_rule_cc_info);
	ip6_rule_cc_info = NULL;
	ip6_rule_tables = 0;
	free(ip6_route_cc_info);
	ip6_route_cc_info = NULL;
	ip6_route_tables = 0;

	return ret;
}

int nf_ipfwd_init(void)
{
	int ret;
#ifdef ENABLE_TRACE
	int i;
#endif

	ret = ipfwd_acquire_cc_info(init.model);
	if (ret) {
		fprintf(stderr,
			"error getting ip4fwd cc info (%d)\n", ret);
		return ret;
	}

	printf("Initializing IPv4 route tables...\n");
	ret = ipfwd_init_tables(ip4_route_cc_info,
				&init.nfapi_init_data.ipfwd.ip4_route_nf_res,
				ip4_route_tables);
	if (ret) {
		error(0, -ret, "Failed to initialize ip4 route tables");
		return ret;
	}

	printf("Initializing IPv4 rule tables...\n");
	ret = ipfwd_init_tables(ip4_rule_cc_info,
				&init.nfapi_init_data.ipfwd.ip4_rule_nf_res,
				ip4_rule_tables);
	if (ret) {
		error(0, -ret, "Failed to initialize ip4 rule tables");
		return ret;
	}

	printf("Initializing IPv6 route tables...\n");
	ret = ipfwd_init_tables(ip6_route_cc_info,
				&init.nfapi_init_data.ipfwd.ip6_route_nf_res,
				ip6_route_tables);
	if (ret) {
		error(0, -ret, "Failed to initialize ip6 route tables");
		return ret;
	}

	printf("Initializing IPv6 rule tables...\n");
	ret = ipfwd_init_tables(ip6_rule_cc_info,
				&init.nfapi_init_data.ipfwd.ip6_rule_nf_res,
				ip6_rule_tables);
	if (ret) {
		error(0, -ret, "Failed to initialize ip6 rule tables");
		return ret;
	}

#ifdef ENABLE_TRACE
	for (i = 0; i < ip4_route_tables; i++)
		ip4_route_cc_node[i] = ip4_route_cc_info[i].handle;
	for (i = 0; i < ip6_route_tables; i++)
		ip6_route_cc_node[i] = ip6_route_cc_info[i].handle;
#endif

	ret = init_nf_ipfwd_global_data();
	if (ret < 0) {
		error(0, -ret, "Failed on init_nf_ipfwd_global_data");
		return ret;
	}

	return 0;
}

static inline int get_out_pol_num(int dpa_ipsec_proto)
{
	int out_pol_cc_node_keys[] = IPSEC_OUT_POL_CC_NODE_KEYS;
	if (dpa_ipsec_proto < 0 ||
	    dpa_ipsec_proto >= DPA_IPSEC_MAX_SUPPORTED_PROTOS)
		return -1;
	return out_pol_cc_node_keys[dpa_ipsec_proto];
}

static inline int get_out_key_size(int dpa_ipsec_proto)
{
	int ob_key_size[] = IPSEC_OUT_PRE_ENC_TBL_KEY_SIZE;
	if (dpa_ipsec_proto < 0 ||
	    dpa_ipsec_proto >= DPA_IPSEC_MAX_SUPPORTED_PROTOS)
		return -1;
	return ob_key_size[dpa_ipsec_proto];
}

static inline int get_ib_key_size(int dpa_ipsec_proto)
{
	int ib_key_size[] = IPSEC_PRE_DEC_TBL_KEY_SIZE;
	if (dpa_ipsec_proto < 0 ||
	    dpa_ipsec_proto >= DPA_IPSEC_MAX_SUPPORTED_PROTOS)
		return -1;
	return ib_key_size[dpa_ipsec_proto];
}

static inline int get_in_sa_hash_ways(int dpa_ipsec_sa_type)
{
	int num_entries[][2] = IPSEC_IN_SA_HASH_ENTRIES;
	if (dpa_ipsec_sa_type < 0 ||
	    dpa_ipsec_sa_type >= DPA_IPSEC_MAX_SA_TYPE)
		return -1;
	return num_entries[dpa_ipsec_sa_type][WAYS];
}
static inline int get_in_sa_hash_sets(int dpa_ipsec_sa_type)
{
	int num_entries[][2] = IPSEC_IN_SA_HASH_ENTRIES;
	if (dpa_ipsec_sa_type < 0 ||
	    dpa_ipsec_sa_type >= DPA_IPSEC_MAX_SA_TYPE)
		return -1;
	return num_entries[dpa_ipsec_sa_type][SETS];
}

static t_Handle *get_ob_ipsec_cc_nodes(void)
{
	uint8_t i = 0, count = 0;
	struct fman_if * __if = NULL;
	t_Handle * cc_nodes = NULL;
	char fmc_path[64] = "";

	__if = get_ipsec_if(OB_OH_PRE);
	if (!__if)
		return NULL;

	cc_nodes = malloc(DPA_IPSEC_MAX_SUPPORTED_PROTOS * sizeof(t_Handle));
	if (!cc_nodes)
		return NULL;

	TRACE("DEBUG: Identified OUTBOUND pre-SEC Cc nodes:\n");
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++) {
		memset(fmc_path, 0, sizeof(fmc_path));
		sprintf(fmc_path, "fm%d/port/%s/%d/ccnode/%s",
				__if->fman_idx,
				type_desc[__if->mac_type],
				__if->mac_idx,
				ob_cc_labels[i]);
		cc_nodes[i] = fmc_get_handle(init.model, fmc_path);
#ifdef ENABLE_TRACE
		ob_pre_cc_node[i] = cc_nodes[i];
		if (ob_pre_cc_node[i])
			printf("\t%d) \"%s\" -> cc_node=0x%x\n", i, fmc_path,
				(unsigned)cc_nodes[i]);
		else
			printf("\t%d) \"%s\" -> [NOT FOUND]\n", i, fmc_path);
#endif /* ENABLE_TRACE */
		if (cc_nodes[i])
			count++;
	}

	if (!count) {
		fprintf(stderr, "No IPSec OB classifications found.\n");
		return NULL;
	}

	return cc_nodes;
}

static t_Handle *get_ib_ipsec_cc_nodes(void)
{
	uint8_t i = 0, count = 0;
	struct fman_if * __if = NULL;
	t_Handle * cc_nodes = NULL;
	char fmc_path[64] = "";

	__if = get_ipsec_if(IB);
	if (!__if)
		return NULL;

	cc_nodes = malloc(DPA_IPSEC_MAX_SA_TYPE * sizeof(t_Handle));
	if (!cc_nodes)
		return NULL;

	TRACE("DEBUG: Identified INBOUND pre-SEC Cc nodes:\n");
	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++) {
		memset(fmc_path, 0, sizeof(fmc_path));
		sprintf(fmc_path, "fm%d/port/%s/%d/ccnode/%s",
				__if->fman_idx, type_desc[__if->mac_type], __if->mac_idx, ib_cc_labels[i]);
		cc_nodes[i] = fmc_get_handle(init.model, fmc_path);
#ifdef ENABLE_TRACE
		ib_pre_cc_node[i] = cc_nodes[i];
		if (ib_pre_cc_node[i])
			TRACE("\t%d) \"%s\" -> cc_node=0x%x\n", i, fmc_path,
				(unsigned)cc_nodes[i]);
		else
			TRACE("\t%d) \"%s\" -> [NOT FOUND]\n", i, fmc_path);
#endif /* ENABLE_TRACE */
		if (cc_nodes[i])
			count++;
	}

	if (!count) {
		fprintf(stderr, "No IPSec IB classifications found.\n");
		return NULL;
	}

	return cc_nodes;
}

static t_Handle *get_ib_policy_verification_cc_nodes(void)
{
	struct fman_if * __if = NULL;
	t_Handle *cc_node = NULL;
	char fmc_path[64] = "";

	__if = get_ipsec_if(IB_OH);
	if (!__if)
		return NULL;

	cc_node = malloc(sizeof(t_Handle));
	if (!cc_node)
		return NULL;

	memset(fmc_path, 0, sizeof(fmc_path));
	sprintf(fmc_path, "fm%d/port/%s/%d/ccnode/%s",
			__if->fman_idx, type_desc[__if->mac_type],
			__if->mac_idx, ib_policy_verification_cc_label);
	*cc_node = fmc_get_handle(init.model, fmc_path);
	fprintf(stderr, "ib_policy_verification_cc_node = %p -%s-\n",
			*cc_node, fmc_path);
	if (!cc_node) {
		fprintf(stderr, "NO IPSec IB policy verification "
				" classification found.\n");
		return NULL;
	}

	return cc_node;

}

static uint8_t init_dpa_ipsec_instance(void)
{
	int i, cls_td, ret;
	t_Handle * cc = NULL;
	struct dpa_cls_tbl_params cls_tbl_params;
	struct dpa_ipsec_params * ipsec_params = &init.nfapi_init_data.ipsec.ipsec_params;
	struct fman_if * _if = NULL;

	memset(ipsec_params, 0, sizeof(struct dpa_ipsec_params));
	ipsec_params->max_sa_pairs = init.nfapi_init_data.ipsec.user_data.max_sa;
	ipsec_params->fm_pcd = init.nfapi_init_data.pcd_dev;
	ipsec_params->ipf_bpid = init.nfapi_init_data.ipsec.ipf_bpid;
	ipsec_params->qm_sec_ch = qm_channel_caam;

	cc = get_ib_ipsec_cc_nodes();
	if (!cc)
		return -1;

	TRACE("DEBUG: Creating INBOUND policy tables (per SA type):\n");
	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++) {
		/* INB/DL pre SEC classifier */
		memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
		cls_tbl_params.cc_node = cc[i];
		cls_tbl_params.type = DPA_CLS_TBL_HASH;
		cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_REF;
		cls_tbl_params.hash_params.hash_offs = IN_SA_PCD_HASH_OFF;
		cls_tbl_params.hash_params.max_ways = get_in_sa_hash_ways(i);
		cls_tbl_params.hash_params.num_sets = get_in_sa_hash_sets(i);
		cls_tbl_params.hash_params.key_size = get_ib_key_size(i);

		ret = dpa_classif_table_create(&cls_tbl_params, &cls_td);
		if (ret < 0) {
			fprintf(stderr, "Error creating inbound SA "
				"classif table (%d), err %d\n", i, ret);
			goto out_ib_pre_sec;
		}

		ipsec_params->pre_sec_in_params.dpa_cls_td[i] = cls_td;
		TRACE("\t- td[%d] = %d; ccnode=0x%x\n", i, cls_td, (unsigned)cc[i]);
	}

	/* INB/DL  post SEC params */
	ipsec_params->post_sec_in_params.data_off =
			(rta_get_sec_era() < RTA_SEC_ERA_5)?
			SEC_DATA_OFF_BURST :
			SEC_ERA_5_DATA_OFF_BURST;
	ipsec_params->post_sec_in_params.base_flow_id = IPSEC_START_IN_FLOW_ID;
	ipsec_params->post_sec_in_params.use_ipv6_pol = false;

	_if = get_ipsec_if(IB_OH);
	if (!_if)
		return -1;
	ipsec_params->post_sec_in_params.qm_tx_ch = _if->tx_channel_id;
	free(cc);

	/* INB policy verification */
	if (init.nfapi_init_data.ipsec.user_data.ib_policy_verification) {
		cc = get_ib_policy_verification_cc_nodes();
		if (!cc)
			return -1;

		memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
		cls_tbl_params.cc_node = *cc;
		cls_tbl_params.type = DPA_CLS_TBL_INDEXED;
		cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_REF;
		cls_tbl_params.indexed_params.entries_cnt =
						ipsec_params->max_sa_pairs;
		ret = dpa_classif_table_create(&cls_tbl_params, &cls_td);
		if (ret < 0) {
			fprintf(stderr,
					"INB post SEC dpa_classif_table_create "
					"failed, err %d\n", ret);
			goto out_ib_post_sec;
		}

		ipsec_params->post_sec_in_params.dpa_cls_td = cls_td;
		ipsec_params->post_sec_in_params.do_pol_check = true;
		ipsec_params->post_sec_in_params.key_fields =
						DPA_IPSEC_KEY_FIELD_DIP;
		free(cc);
	} else {
		ipsec_params->post_sec_in_params.do_pol_check = false;
		ipsec_params->post_sec_in_params.dpa_cls_td =
						DPA_OFFLD_DESC_NONE;
		printf("IB policy verification not activated\n");
	}

	/* OUTB/UL post SEC params */
	ipsec_params->post_sec_out_params.data_off =
			 (rta_get_sec_era() < RTA_SEC_ERA_5)?
			 SEC_DATA_OFF_BURST :
			 SEC_ERA_5_DATA_OFF_BURST;

	_if = get_ipsec_if(OB_OH_POST);
	if (!_if)
		return -1;
	ipsec_params->post_sec_out_params.qm_tx_ch = _if->tx_channel_id;

	/* OUTB/UL pre SEC params */
	cc = get_ob_ipsec_cc_nodes();
	if (!cc)
		goto out_ob_pre_sec;

	TRACE("DEBUG: Creating OUTBOUND policy tables (per protocol):\n");
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++) {
		if (cc[i] != NULL) {
			memset(&cls_tbl_params, 0, sizeof(cls_tbl_params));
			cls_tbl_params.cc_node = cc[i];
			cls_tbl_params.type = DPA_CLS_TBL_EXACT_MATCH;
			cls_tbl_params.entry_mgmt = DPA_CLS_TBL_MANAGE_BY_REF;
			cls_tbl_params.exact_match_params.entries_cnt =	get_out_pol_num(i);
			cls_tbl_params.exact_match_params.key_size = get_out_key_size(i);

			ret = dpa_classif_table_create(&cls_tbl_params, &cls_td);
			if (ret < 0) {
				fprintf(stderr, "Error creating outbound "
					"classif table (%d),err %d\n", i, ret);
				goto out_ib_pre_sec;
			}

			ipsec_params->pre_sec_out_params.table[i].dpa_cls_td = cls_td;
			TRACE("\t- td[%d] = %d; ccnode=0x%x\n", i, cls_td, (unsigned)cc[i]);

			if (i == DPA_IPSEC_PROTO_ICMP_IPV4 || i == DPA_IPSEC_PROTO_ICMP_IPV6)
				ipsec_params->pre_sec_out_params.table[i].key_fields =
					IPSEC_OUT_POL_ICMP_KEY_FIELDS;
			else
				ipsec_params->pre_sec_out_params.table[i].key_fields =
					IPSEC_OUT_POL_TCPUDP_KEY_FIELDS;
		} else
			ipsec_params->pre_sec_out_params.table[i].dpa_cls_td =
							DPA_OFFLD_DESC_NONE;
	}

	free(cc);
	ret = dpa_ipsec_init(ipsec_params, &init.nfapi_init_data.ipsec.dpa_ipsec_id);
	if (ret < 0) {
		fprintf(stderr, "dpa_ipsec_init failed\n");
		goto out_ob_pre_sec;
	}

	return 0;
out_ob_pre_sec:
	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++)
		if (ipsec_params->pre_sec_out_params.table[i].dpa_cls_td !=
			DPA_OFFLD_DESC_NONE)
			dpa_classif_table_free(ipsec_params->pre_sec_out_params.table[i].dpa_cls_td);
out_ib_post_sec:
	/* TODO: free post_set table */

out_ib_pre_sec:
	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++)
		if (ipsec_params->pre_sec_in_params.dpa_cls_td[i] !=
			DPA_OFFLD_DESC_NONE)
			dpa_classif_table_free(ipsec_params->pre_sec_in_params.
						dpa_cls_td[i]);

	return -1;
}

static int create_fq_outbound_bypass(uint16_t channel, uint32_t *nf_ipsec_fq_id)
{

	struct qman_fq fq_out;
	struct qm_mcc_initfq fq_opts;
	int fq_id = 0, ret = 0;

	memset(&fq_out, 0, sizeof(struct qman_fq));

	ret = qman_create_fq(fq_id,
		QMAN_FQ_FLAG_NO_ENQUEUE | QMAN_FQ_FLAG_DYNAMIC_FQID, &fq_out);
	BUG_ON(ret);

	memset(&fq_opts, 0, sizeof(fq_opts));
	fq_opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	fq_opts.fqd.dest.wq = 0;
	fq_opts.fqd.dest.channel = channel;

	ret = qman_init_fq(&fq_out, QMAN_INITFQ_FLAG_SCHED, &fq_opts);
	if (unlikely(ret < 0)) {
		error(0, ret, "Unable to initialize Outbound IPSec frame queue(FQID=%d)\n",
				fq_out.fqid);
		return ret;
	}

	*nf_ipsec_fq_id = fq_id;
	return 0;
}

static void teardown_fq(struct qman_fq *fq)
{
	u32 flags;
	int s = qman_retire_fq(fq, &flags);
	if (s == 1) {
		/* Retire is non-blocking, poll for completion */
		enum qman_fq_state state;
		do {
			qman_poll();
			qman_fq_state(fq, &state, &flags);
		} while (state != qman_fq_state_retired);
		if (flags & QMAN_FQ_STATE_NE) {
			/* FQ isn't empty, drain it */
			s = qman_volatile_dequeue(fq, 0,
				QM_VDQCR_NUMFRAMES_TILLEMPTY);
			if (s) {
				fprintf(stderr, "Fail: %s: %d\n",
					"qman_volatile_dequeue()", s);
				return;
			}
			/* Poll for completion */
			do {
				qman_poll();
				qman_fq_state(fq, &state, &flags);
			} while (flags & QMAN_FQ_STATE_VDQCR);
		}
	}
	s = qman_oos_fq(fq);
	if (!(fq->flags & QMAN_FQ_FLAG_DYNAMIC_FQID))
		qman_release_fqid(fq->fqid);
	if (s)
		fprintf(stderr, "Fail: %s: %d\n", "qman_oos_fq()", s);
	else
		qman_destroy_fq(fq, 0);
}

int nf_ipsec_init(void)
{
	int ret = 0;

	ret = init_nf_ipsec_global_data();
	if (ret < 0) {
		fprintf(stderr, "Failed to init global data");
		return ret;
	}

	ret = dpa_ipsec_lib_init();
	if (ret < 0) {
		fprintf(stderr, "dpa_ipsec_lib_init failed, err %d\n", ret);
		dpa_classif_lib_exit();
		return ret;
	}

	ret = init_dpa_ipsec_instance();
	if (ret < 0) {
		fprintf(stderr, "DPA IPsec init failure (%d)\n", ret);
		goto out;
	}

	ret = reconfigure_tables();
	if (ret < 0)
		goto out;

	ret = create_fq_outbound_bypass(
			gbl_init->ipsec.ipsec_params.post_sec_out_params.qm_tx_ch,
			&gbl_init->ipsec.fqid);
	if (ret < 0)
		goto out;

	return 0;

out:
	dpa_ipsec_lib_exit();
	dpa_classif_lib_exit();
	return -1;
}

void nf_ipsec_cleanup(void)
{
	int i, ret;
	int id = init.nfapi_init_data.ipsec.dpa_ipsec_id;
	struct dpa_ipsec_params * ipsec_params = &init.nfapi_init_data.ipsec.ipsec_params;

	if (id < 0)
		return;

	ret = dpa_ipsec_free(id);
	if (ret < 0) {
		fprintf(stderr, "%s:%d: error freeing dpa ipsec instance %d\n",
			__func__, __LINE__, id);
		return;
	}

	for (i = 0; i < DPA_IPSEC_MAX_SA_TYPE; i++)
		dpa_classif_table_free(
				ipsec_params->pre_sec_in_params.dpa_cls_td[i]);

	for (i = 0; i < DPA_IPSEC_MAX_SUPPORTED_PROTOS; i++)
		if (ipsec_params->pre_sec_out_params.table[i].dpa_cls_td !=
							DPA_OFFLD_DESC_NONE)
			dpa_classif_table_free(
					ipsec_params->pre_sec_out_params.
					table[i].dpa_cls_td);
	/* TODO: remove bypass queue */
	/* TODO: remove port queues */
}

static void net_if_finish(struct net_if *interface)
{
	const struct fman_if *fif = interface->cfg->fman_if;
	struct net_if_rx_fqrange *rx_fqrange;
	unsigned loop;

	/* Disable Rx */
	fman_if_disable_rx(fif);

	/* Cleanup Rx FQs */
	list_for_each_entry(rx_fqrange, &interface->rx_list, list)
		for (loop = 0; loop < rx_fqrange->rx_count; loop++)
			teardown_fq(&rx_fqrange->rx[loop].fq);

#if 0
	/* Cleanup admin FQs */
	if (net_if_admin_is_used(interface, ADMIN_FQ_RX_ERROR))
		teardown_fq(&interface->admin[ADMIN_FQ_RX_ERROR].fq);
	if (net_if_admin_is_used(interface, ADMIN_FQ_RX_DEFAULT))
		teardown_fq(&interface->admin[ADMIN_FQ_RX_DEFAULT].fq);
	if (net_if_admin_is_used(interface, ADMIN_FQ_TX_ERROR))
		teardown_fq(&interface->admin[ADMIN_FQ_TX_ERROR].fq);
	if (net_if_admin_is_used(interface, ADMIN_FQ_TX_CONFIRM))
		teardown_fq(&interface->admin[ADMIN_FQ_TX_CONFIRM].fq);

	/* Cleanup Tx FQs */
	for (loop = 0; loop < interface->num_tx_fqs; loop++)
		teardown_fq(&interface->tx_fqs[loop]);
#endif
}

static void cleanup_buffer_pools(void)
{
	dma_mem_destroy(dma_mem_generic);
	bman_release_bpid(init.nfapi_init_data.ipsec.ipf_bpid);
}

static void do_library_finish(void)
{
	struct list_head *i;

	/* Tear down the network interfaces */
	list_for_each(i, &init.nfapi_init_data.ifs)
		net_if_finish((struct net_if *)i);

	if (init.is_ipsec)
		nf_ipsec_cleanup();
	/*
	 * TODO: add ipfwd cleanup
	 * if (init.is_ipfwd)
	 *	;
	 */

	fmc_clean(init.model);
	cleanup_buffer_pools();
}

/* This struct holds the default stashing opts for Rx FQ configuration*/
static const struct qm_fqd_stashing default_stash_opts = {
	.annotation_cl = 0,
	.data_cl = 1,
	.context_cl = 0
};


/* Drop a frame (releases buffers to Bman) */
static inline void drop_frame(const struct qm_fd *fd)
{
	struct bm_buffer buf;
	int ret;

	BUG_ON(fd->format != qm_fd_contig);
	BUG_ON(fd->bpid >= MAX_BPID);
	bm_buffer_set64(&buf, qm_fd_addr(fd));

retry:
	ret = bman_release(init.pool[fd->bpid], &buf, 1, 0);
	if (ret) {
		cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
		goto retry;
	}
	printf("drop: bpid %d <-- 0x%llx\n", fd->bpid, qm_fd_addr(fd));

#ifdef ORDER_RESTORATION
	/* Perform a "HOLE" enqueue so that the ORP doesn't wait for the
	 * sequence number that we're dropping. */
	if (!local_orp_fq)
		return;
retry_orp:
	ret = qman_enqueue_orp(local_orp_fq, fd, QMAN_ENQUEUE_FLAG_HOLE,
			       local_orp_fq, local_seqnum);
	if (ret) {
		cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
		goto retry_orp;
	}
	printf("drop: fqid %d <-- 0x%x (HOLE)\n",
		local_orp_fq->fqid, local_seqnum);
#endif
}


/* DQRR callback used by Tx FQs (used when retiring and draining) as well as
 * admin FQs ([rt]x_error, rx_default, tx_confirm). */
static enum qman_cb_dqrr_result cb_tx_drain(struct qman_portal *qm __always_unused,
				      struct qman_fq *fq __always_unused,
				      const struct qm_dqrr_entry *dqrr)
{
	printf("Tx_drain: fqid=%d\tfd_status = 0x%08x\n", fq->fqid,
			dqrr->fd.status);
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result
cb_dqrr_tx_error(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
	printf("Tx_error: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result
cb_dqrr_tx_confirm(struct qman_portal *qm __always_unused,
		   struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	printf("TX_confirm fqid=%dfd_status = 0x%08x\n",
			fq->fqid, dqrr->fd.status);
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}


static enum qman_cb_dqrr_result cb_dqrr_rx_default
			(struct qman_portal *qm __always_unused, struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	printf("Rx_default: fqid=%d\tfd_status = 0x%08x\n", fq->fqid, dqrr->fd.status);
	drop_frame(&dqrr->fd);
	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result cb_dqrr_rx_error
		(struct qman_portal *qm __always_unused,
		 struct qman_fq *fq,
		 const struct qm_dqrr_entry *dqrr)
{
#ifdef ENABLE_TRACE
	u8 *data = NULL;
	unsigned i, size = 0;
#endif
	const struct qm_fd *fd = &dqrr->fd;

	switch (fd->format) {
	case qm_fd_contig:
		printf("Rx_error (qm_fd_contig): fqid=0x%x, size=%u (bytes), fd_status=0x%08x\n",
			fq->fqid, fd->length20, dqrr->fd.status);
#ifdef ENABLE_TRACE
		size = fd->length20;
		data = __dma_mem_ptov(qm_fd_addr(fd)) + fd->offset;
#endif
		break;
	case qm_fd_sg:
		printf("Rx_error (qm_fd_sg): fqid=0x%x, size=%u (bytes), fd_status=0x%08x\n",
			fq->fqid, fd->length20, dqrr->fd.status);
		break;
	case qm_fd_contig_big:
		printf("Rx_error (qm_fd_contig_big): fqid=0x%x, size=%u (bytes), fd_status=0x%08x\n",
			fq->fqid, fd->length29, dqrr->fd.status);
#ifdef ENABLE_TRACE
		size = fd->length29;
		data = __dma_mem_ptov(qm_fd_addr(fd));
#endif
		break;
	case qm_fd_sg_big:
		printf("Rx_error (qm_fd_sg_big): fqid=0x%x, size=%u (bytes), fd_status=0x%08x\n",
			fq->fqid, fd->length29, dqrr->fd.status);
		break;
	default:
		printf("Rx_error: fqid=0x%x, fd_status=0x%08x\n", fq->fqid, dqrr->fd.status);
		break;
	}

#ifdef ENABLE_TRACE
	if (size > 0) {
		if (size < FRAME_CONTENT_DEBUG_DUMP_LEN)
			printf("\nDEBUG dump frame content:\n");
		else {
			printf("\nDEBUG dump frame content (first %d bytes):\n",
				FRAME_CONTENT_DEBUG_DUMP_LEN);
			size = FRAME_CONTENT_DEBUG_DUMP_LEN;
		}

		for (i = 0; i < size; i++) {
			if (i % 16 == 0)
				printf("0x%02x: ", i);
			printf("%02x ", data[i]);
			if ((i+1) % 16 == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif /* ENABLE_TRACE */

	/* don't drop BPDERR SEC errored fds */
	if ((dqrr->fd.status & SEC_QI_ERR_MASK) == SEC_QI_ERR_BITS &&
	    (dqrr->fd.status & SEC_QI_STA_MASK) == SEC_QI_ERR_BPD)
		return qman_cb_dqrr_consume;

	drop_frame(&dqrr->fd);

	return qman_cb_dqrr_consume;
}


/* Transmit a frame */
static inline void send_frame(u32 fqid, const struct qm_fd *fd)
{
	int ret;
	local_fq.fqid = fqid;
retry:
	ret = qman_enqueue(&local_fq, fd, 0);
	if (ret) {
		cpu_spin(CPU_SPIN_BACKOFF_CYCLES);
		goto retry;
	}
}

/* DQRR callback for Rx FQs */
static enum qman_cb_dqrr_result cb_rx(struct qman_portal *qm __always_unused,
				      struct qman_fq *fq,
				      const struct qm_dqrr_entry *dqrr)
{
#ifdef ENABLE_TRACE
	u8 *data = NULL;
	unsigned i, size = 0;
#endif
	const struct qm_fd *fd = &dqrr->fd;

	switch (fd->format) {
	case qm_fd_contig:
		printf("Rx (qm_fd_contig): fqid=0x%x, size=%u (bytes)\n", fq->fqid, fd->length20);
#ifdef ENABLE_TRACE
		size = fd->length20;
		data = __dma_mem_ptov(qm_fd_addr(fd)) + fd->offset;
#endif
		break;
	case qm_fd_sg:
		printf("Rx (qm_fd_sg): fqid=0x%x, size=%u (bytes)\n", fq->fqid, fd->length20);
		break;
	case qm_fd_contig_big:
		printf("Rx (qm_fd_contig_big): fqid=0x%x, size=%u (bytes)\n", fq->fqid, fd->length29);
#ifdef ENABLE_TRACE
		size = fd->length29;
		data = __dma_mem_ptov(qm_fd_addr(fd));
#endif
		break;
	case qm_fd_sg_big:
		printf("Rx (qm_fd_sg_big): fqid=0x%x, size=%u (bytes)\n", fq->fqid, fd->length29);
		break;
	default:
		printf("Rx packet: fqid=0x%x\n", fq->fqid);
		break;
	}

#ifdef ENABLE_TRACE
	if (size > 0) {
		if (size < FRAME_CONTENT_DEBUG_DUMP_LEN)
			printf("\nDEBUG dump frame content:\n");
		else {
			printf("\nDEBUG dump frame content (first %d bytes):\n",
				FRAME_CONTENT_DEBUG_DUMP_LEN);
			size = FRAME_CONTENT_DEBUG_DUMP_LEN;
		}

		for (i = 0; i < size; i++) {
			if (i % 16 == 0)
				printf("0x%02x: ", i);
			printf("%02x ", data[i]);
			if ((i+1) % 16 == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif /* ENABLE_TRACE */

	drop_frame(fd);

	return qman_cb_dqrr_consume;
}

void net_if_rx_fq_init(struct qman_fq *fq, u32 fqid,
		      u16 channel,
		      const struct qm_fqd_stashing *stashing,
		      int prefer_in_cache)
{
	struct qm_mcc_initfq opts;
	__maybe_unused int ret;
	fq->cb.dqrr = cb_rx;

	ret = qman_reserve_fqid(fqid);
	BUG_ON(ret);

	ret = qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq);
	BUG_ON(ret);
	/* FIXME: no taildrop/holdactive for "2fwd" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = PRIORITY_2FWD;
	opts.fqd.fq_ctrl =
#ifdef HOLDACTIVE
		QM_FQCTRL_HOLDACTIVE |
#endif
#ifdef AVOIDBLOCK
		QM_FQCTRL_AVOIDBLOCK |
#endif
		QM_FQCTRL_CTXASTASHING;
	if (prefer_in_cache)
		opts.fqd.fq_ctrl |= QM_FQCTRL_PREFERINCACHE;
#ifdef PPAC_CGR
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr_rx.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
	opts.fqd.context_a.stashing = *stashing;
	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(ret);
}

static int rx_hash_init(struct net_if_rx *p, struct net_if *p_if,
			unsigned idx,
			struct qm_fqd_stashing *stash_opts __always_unused)
{
	static struct net_if *ib_oh_if = NULL, *ob_oh_if = NULL, *eth_if = NULL;
	struct net_if *n_if = NULL;

	if (!ib_oh_if && !ob_oh_if && !eth_if) {
		list_for_each_entry(n_if, &init.nfapi_init_data.ifs, node) {
			/* offline ports */
			if (n_if->cfg->fman_if == get_ipsec_if(IB))
				ib_oh_if = n_if;
			else if (n_if->cfg->fman_if == get_ipsec_if(OB_OH_PRE))
				ob_oh_if = n_if;

			/* ethernet port */
			if (n_if->cfg->fman_if == get_ipsec_if(OB))
				eth_if = n_if;
		}
	}

	/* one or more ports were not found */
	if (!ib_oh_if || !ob_oh_if || !eth_if) {
		printf("WARNING: Failed to identify all IPSec ports from XML configuration.\n");
		return 0;
	}

	/* inbound mappings : inbound offline Rx - ethernet Tx*/
	if (ib_oh_if == p_if) {
		p->tx_fqid = ib_oh_if->tx_fqs[idx % ib_oh_if->num_tx_fqs].fqid;
		printf("Mapping Rx FQ %p:%d --> Tx FQID %d\n", p, idx, p->tx_fqid);
	}

	/* outbound mappings : ethernet Rx - outbound offline Tx*/
	if (eth_if == p_if) {
		p->tx_fqid = eth_if->tx_fqs[idx % eth_if->num_tx_fqs].fqid;
		printf("Mapping Rx FQ %p:%d --> Tx FQID %d\n", p, idx, p->tx_fqid);
	}

	return 0;
}

void net_if_admin_fq_init(struct qman_fq *fq, u32 fqid,
			 u16 channel,
			 const struct qm_fqd_stashing *stashing,
			 qman_cb_dqrr cb)
{
	struct qm_mcc_initfq opts;

	if (qman_reserve_fqid(fqid))
		return;

	fq->cb.dqrr = cb;

	if (qman_create_fq(fqid, QMAN_FQ_FLAG_NO_ENQUEUE, fq))
		return;

	/* FIXME: no taildrop/holdactive for "2drop" FQs */
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = PRIORITY_2DROP;
	opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING;
	opts.fqd.context_a.stashing = *stashing;

	qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
}


/* Utility to select one of the available pool channels in a round-robin manner.
 * As software-consumed FQs are initialised, this function is called each time
 * in order to spread the FQs around the pool-channels. */
static u16 get_next_rx_channel(void)
{
	u16 ret = init.pchannels[init.pchannel_idx];
	init.pchannel_idx = (init.pchannel_idx + 1) % NUM_POOL_CHANNELS;
	return ret;
}


static int net_if_rx_init(struct net_if * i)
{
	__maybe_unused int err;
	unsigned loop;
	struct qm_fqd_stashing stash_opts;
	const struct fman_if *fif = i->cfg->fman_if;
	struct fm_eth_port_fqrange *fqr;

	INIT_LIST_HEAD(&i->rx_list);

	stash_opts = default_stash_opts;

	if (fif->mac_type == fman_mac_less) {
		uint32_t fqid = fif->macless_info.tx_start;
		i->rx_default = malloc(fif->macless_info.tx_count * sizeof(struct qman_fq));
		if (i->rx_default)
			return -ENOMEM;

		for (loop = 0; loop < fif->macless_info.tx_count; loop++) {
			net_if_admin_fq_init(&i->rx_default[loop], fqid++,
				get_next_rx_channel(), &stash_opts, cb_dqrr_rx_default);
			fprintf(stderr, "INFO: macless net_if_admin_fq_init for rx_default[%d]=%u\n",
					loop, qman_fq_fqid(&i->rx_default[loop]));
		}

		usdpaa_netcfg_enable_disable_shared_rx(i->cfg->fman_if, true);
		return 0;
	}

	i->rx_default = malloc(sizeof(struct qman_fq));

	if (fif->mac_type == fman_onic) {
		uint32_t fqid = fif->fqid_rx_def;
		net_if_admin_fq_init(&i->rx_error,	fif->fqid_rx_err,
				get_next_rx_channel(), &stash_opts, cb_dqrr_rx_error);
		fprintf(stderr, "INFO: onic net_if_admin_fq_init for rx_error=%u\n",
				qman_fq_fqid(&i->rx_error));
		net_if_admin_fq_init(&i->rx_default[0], fqid++,
				get_next_rx_channel(), &stash_opts, cb_dqrr_rx_default);
		fprintf(stderr, "INFO: onic net_if_admin_fq_init for rx_default[0]=%u\n",
				qman_fq_fqid(&i->rx_default[0]));

		usdpaa_netcfg_enable_disable_shared_rx(i->cfg->fman_if, true);
		return 0;
	}

	if (fif->shared_mac_info.is_shared_mac) {
		struct qm_mcr_queryfq_np np;
		struct qman_fq fq;
		fq.fqid = i->cfg->rx_def;
		err = qman_query_fq_np(&fq, &np);
		if (err) {
			error(0, err, "%s(): shared MAC query FQ", __func__);
			return err;
		}
		/* For shared MAC, initialize default FQ only if state is OOS */
		if (np.state == qman_fq_state_oos) {
			net_if_admin_fq_init(&i->rx_default[0], i->cfg->rx_def,
						get_next_rx_channel(), &stash_opts, cb_dqrr_rx_default);
			fprintf(stderr, "INFO: shared net_if_admin_fq_init for state oos and rx_default[0]=%u\n",
					qman_fq_fqid(&i->rx_default[0]));
		}

	}
	else {
		net_if_admin_fq_init(&i->rx_error, fif->fqid_rx_err,
				get_next_rx_channel(), &stash_opts,
				cb_dqrr_rx_error);
		stash_opts = default_stash_opts;
		net_if_admin_fq_init(&i->rx_default[0], i->cfg->rx_def,
				get_next_rx_channel(), &stash_opts,
				cb_dqrr_rx_default);
	}


	list_for_each_entry(fqr, i->cfg->list, list) {
		uint32_t fqid = fqr->start;
		struct net_if_rx_fqrange *newrange = malloc(sizeof(*newrange));
		if (!newrange)
			return -ENOMEM;

		INIT_LIST_HEAD(&newrange->list);
		newrange->rx_count = fqr->count;

		newrange->rx = __dma_mem_memalign(MAX_CACHELINE,
				newrange->rx_count * sizeof(newrange->rx[0]));
		if (!newrange->rx)
			return -ENOMEM;

		memset(newrange->rx, 0,
			       newrange->rx_count * sizeof(newrange->rx[0]));

		for (loop = 0; loop < fqr->count; loop++) {
			stash_opts = default_stash_opts;
			err = rx_hash_init(&newrange->rx[loop], i, loop, &stash_opts);

#ifdef ORDER_RESTORATION
			newrange->rx[loop].orp_fq = orp_init();
			printf("I/F %d, Rx FQID %d associated with ORP ID %d\n",
				idx, newrange->rx[loop].fq.fqid,
				newrange->rx[loop].orp_id);
#endif
			net_if_rx_fq_init(&newrange->rx[loop].fq, fqid++,
				get_next_rx_channel(), &stash_opts,
				(fif->mac_type == fman_mac_1g) ? RX_1G_PIC :
				(fif->mac_type == fman_mac_10g) ? RX_10G_PIC :
				(fif->mac_type == fman_offline) ? RX_OFFLINE_PIC:
				(fif->mac_type == fman_onic) ? RX_ONIC_PIC:
				0);
		}
		list_add_tail(&newrange->list, &i->rx_list);
	}

	fman_if_enable_rx(i->cfg->fman_if);
	printf ("Interface fman %d, index %d: enable rx\n",
			i->cfg->fman_if->fman_idx,
			i->cfg->fman_if->mac_idx);

	if (fif->shared_mac_info.is_shared_mac == 1){
		usdpaa_netcfg_enable_disable_shared_rx(i->cfg->fman_if, true);
		printf("Interface name %s: enabled RX\n",
				fif->shared_mac_info.shared_mac_name);
	}

	return 0;
}

void net_if_tx_fq_init(struct qman_fq *fq, const struct fman_if *fif,
					   uint32_t flags)
{
	struct qm_mcc_initfq opts;
	__maybe_unused int err;
	 uint64_t context_a = 0, context_b = 0;

	 flags |= QMAN_FQ_FLAG_TO_DCPORTAL;
	/* These FQ objects need to be able to handle DQRR callbacks, when
	 * cleaning up. */
	fq->cb.dqrr = cb_tx_drain;
	if (!fq->fqid)
		flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;
	else {
		err = qman_reserve_fqid(fq->fqid);
		BUG_ON(err);
	}
	err = qman_create_fq(fq->fqid, flags, fq);
	/* Note: handle errors here, BUG_ON()s are compiled out in performance
	 * builds (ie. the default) and this code isn't even
	 * performance-sensitive. */
	BUG_ON(err);
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA;
	opts.fqd.dest.channel = fif->tx_channel_id;
	opts.fqd.dest.wq = PRIORITY_2TX;
	opts.fqd.fq_ctrl = 0;
#ifdef TX_PREFERINCACHE
	opts.fqd.fq_ctrl |= QM_FQCTRL_PREFERINCACHE;
#endif
#ifdef TX_FORCESFDR
	opts.fqd.fq_ctrl |= QM_FQCTRL_FORCESFDR;
#endif
#if defined(PPAC_CGR)
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = cgr_tx.cgrid;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
	opts.fqd.context_b = context_b;

#ifdef TX_CONFIRM
	context_b = fif->fqid_tx_confirm;
#else
	if (fif->mac_type != fman_onic)
		context_a = (uint64_t)1 << 63;

	if (!(flags & TX_FQ_NO_BUF_DEALLOC))
		context_a |= ((uint64_t)fman_dealloc_bufs_mask_hi << 32) |
					(uint64_t)fman_dealloc_bufs_mask_lo;
	if (flags & TX_FQ_NO_CHECKSUM)
		context_a |= FMAN_CONTEXTA_DIS_CHECKSUM;
        if (flags & TX_FQ_SET_OPCODE11)
                context_a |= FMAN_CONTEXTA_SET_OPCODE11;
#endif

	qm_fqd_context_a_set64(&opts.fqd, context_a);
	err = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	BUG_ON(err);
}

/* Initialize a network interface */
static int net_if_init(unsigned idx)
{
	unsigned loop;
	size_t size;
	struct net_if *i;
	struct qm_fqd_stashing stash_opts;
	uint32_t flags = 0;

	const struct fm_eth_port_cfg *cfg = &init.nfapi_init_data.netcfg->port_cfg[idx];
	const struct fman_if *fif = cfg->fman_if;

	/* compute the size of the net if object - may vary depending on if type*/
	if (fif->mac_type == fman_mac_less) {
		size = sizeof(struct net_if) +
			(fif->macless_info.tx_count * sizeof(struct qman_fq));
	} else {
		size = sizeof(struct net_if) + sizeof(struct qman_fq);
	}

	/* allocate stashable memory for the interface object */

	i = __dma_mem_memalign(L1_CACHE_BYTES, size);
	if (!i)
		return -ENOMEM;

	memset(i, 0, size);

	i->size = size;
	i->cfg = cfg;

	/* allocate and initialize Tx FQs for this interface */
	switch (fif->mac_type) {
		case fman_onic:
			i->num_tx_fqs = NUM_TX_FQS_ONIC;
			break;
		case fman_mac_less:
			i->num_tx_fqs = fif->macless_info.tx_count;
			break;
		case fman_mac_10g:
			i->num_tx_fqs = NUM_TX_FQS_10G;
			break;
		case fman_mac_1g:
			i->num_tx_fqs = NUM_TX_FQS_1G;
			break;
		case fman_offline:
			i->num_tx_fqs = NUM_TX_FQS_OFFLINE;
			break;
	}

	i->tx_fqs = malloc(sizeof(*i->tx_fqs) * i->num_tx_fqs);
	if (!i->tx_fqs) {
		__dma_mem_free(i);
		return -ENOMEM;
	}

	memset(i->tx_fqs, 0, sizeof(*i->tx_fqs) * i->num_tx_fqs);

	if (fif->mac_type == fman_mac_less) {
		uint32_t fqid = fif->macless_info.tx_start;
		for (loop = 0; loop < i->num_tx_fqs; loop++) {
			printf("TX FQID %d, count %d\n", fqid, i->num_tx_fqs);
			i->tx_fqs[loop].fqid = fqid++;
		}
		list_add_tail(&i->node, &init.nfapi_init_data.ifs);
		return 0;
	}

	for (loop = 0; loop < i->num_tx_fqs; loop++) {
		struct qman_fq *fq = &i->tx_fqs[loop];
		net_if_tx_fq_init(fq, fif, flags);
	}

	/* Offline ports don't have Tx Error or Tx Confirm FQs */
	if (fif->mac_type == fman_offline || fif->mac_type == fman_onic) {
		list_add_tail(&i->node, &init.nfapi_init_data.ifs);
		return 0;
	}

	/* For shared MAC, Tx Error and Tx Confirm FQs are created by linux */
	if (fif->shared_mac_info.is_shared_mac != 1) {
		stash_opts = default_stash_opts;
		net_if_admin_fq_init(&i->tx_error, fif->fqid_tx_err,
				get_next_rx_channel(), &stash_opts, cb_dqrr_tx_error);

		stash_opts = default_stash_opts;
		net_if_admin_fq_init(&i->tx_confirm, fif->fqid_tx_confirm,
				get_next_rx_channel(), &stash_opts, cb_dqrr_tx_confirm);

	}
	list_add_tail(&i->node, &init.nfapi_init_data.ifs);
	return 0;
}

//TODO: read buffer pools from DTS!
/* IP fragmentation scratch buffer pool
 * move those to header if not patched from dts */
#define DMA_MEM_IPF_SIZE	1600
#define DMA_MEM_IPF_NUM		0x0
/* Interfaces and OP buffer pool */
#define IF_BPID			16
#define DMA_MEM_IF_SIZE		1728
#define DMA_MEM_IF_NUM		0x4000
static struct bpool {
	int bpid;
	unsigned int num;
	unsigned int size;
} bpool[] = {
	{ -1,		DMA_MEM_IPF_NUM,	DMA_MEM_IPF_SIZE },
	{ IF_BPID,	DMA_MEM_IF_NUM,		DMA_MEM_IF_SIZE },
	{ -1,		0,			0 }
};

static int prepare_bpid(u8 bpid, unsigned int count, uint64_t sz,
		      unsigned int align,
		      int to_drain,
		      void (*notify_cb)(struct bman_portal *,
					struct bman_pool *,
					void *cb_ctx,
					int depleted) __always_unused,
		      void *cb_ctx __always_unused)
{
	struct bman_pool_params params = {
		.bpid	= bpid,
	};
	struct bm_buffer bufs[8];
	unsigned int num_bufs = 0;
	int ret = 0;

	if (init.pool[bpid])
		/* this BPID is already handled */
		return 0;
	init.pool[bpid] = bman_new_pool(&params);
	if (!init.pool[bpid]) {
		fprintf(stderr, "error: bman_new_pool(%d) failed\n", bpid);
		return -ENOMEM;
	}
	ret = bman_reserve_bpid(bpid);
	BUG_ON(ret);

	/* Drain the pool of anything already in it. */
	if (to_drain)
	do {
		/* Acquire is all-or-nothing, so we drain in 8s, then in 1s for
		 * the remainder. */
		if (ret != 1)
			ret = bman_acquire(init.pool[bpid], bufs, 8, 0);
		if (ret < 8)
			ret = bman_acquire(init.pool[bpid], bufs, 1, 0);
		if (ret > 0)
			num_bufs += ret;
	} while (ret > 0);
	if (num_bufs)
		fprintf(stderr, "Warn: drained %u bufs from BPID %d\n",
			num_bufs, bpid);
	/* Fill the pool */
	for (num_bufs = 0; num_bufs < count; ) {
		unsigned int loop, rel = (count - num_bufs) > 8 ? 8 :
					(count - num_bufs);
		for (loop = 0; loop < rel; loop++) {
			void *ptr;
			if (!align)
				ptr = __dma_mem_memalign(64, sz);
			else
				ptr = __dma_mem_memalign(align, sz);
			if (!ptr) {
				fprintf(stderr, "error: no buffer space\n");
				abort();
			}
			bm_buffer_set64(&bufs[loop], __dma_mem_vtop(ptr));
		}
		do {
			ret = bman_release(init.pool[bpid], bufs, rel, 0);
		} while (ret == -EBUSY);
		if (ret)
			fprintf(stderr, "Fail: %s\n", "bman_release()");
		num_bufs += rel;
	}
	printf("Released %u bufs to BPID %d\n", num_bufs, bpid);
	return 0;
}

static int init_buffer_pools(void)
{
	int ret;
	const struct bpool *bp = bpool;
	uint32_t * ipf_bpid = &init.nfapi_init_data.ipsec.ipf_bpid;

	ret = bman_alloc_bpid(ipf_bpid);
	if (ret < 0) {
		fprintf(stderr, "Cannot allocate bpid for ipf bpool\n");
		return ret;
	}
	bpool[0].bpid = *ipf_bpid;

	while (bp->bpid != -1) {
		ret = prepare_bpid(bp->bpid, bp->num, bp->size, 256,
				           (uint32_t)(bp->bpid) == *ipf_bpid ? 0 : 1,
					       NULL, NULL);
		if (ret) {
			fprintf(stderr, "error: bpool (%d) init failure\n",
				bp->bpid);
			return ret;
		}
		bp++;
	}

	return 0;
}

static int set_dist_base_fqid(
	struct fmc_model_t *_cmodel,
	char *fmc_path,
	uint32_t fqid)
{
	unsigned i = 0;
	for (i = 0; i < _cmodel->scheme_count; i++) {
		if (!strcmp(_cmodel->scheme_name[i], fmc_path)) {
			_cmodel->scheme[i].baseFqid = fqid;
			return 0;
		}
	}
	return -ENODEV;
}


/* Patch default queues for OUTBOUND IPSec distributions. */
static int update_ipsec_ob_default_fq(void)
{
	char fmc_path[64];
	int ret;
	unsigned i;
	struct fman_if *f_ob_rx, *f_ob_oh_pre;
	struct net_if *n_if;
	u32 ob_oh_pre_fqid = 0;

	f_ob_rx = init.nfapi_init_data.ipsec.ifs_by_role[OB];
	if (!f_ob_rx) {
		error(0, ENODEV, "FMan OUTBOUND interface not found");
		return -ENODEV;
	}
	f_ob_oh_pre = get_ipsec_if(OB_OH_PRE);
	if (!f_ob_oh_pre) {
		error(0, ENODEV, "FMan OUTBOUND OH PRE SEC not found");
		return -ENODEV;
	}

	list_for_each_entry(n_if, &init.nfapi_init_data.ifs, node) {
		if (n_if->cfg->fman_if == f_ob_oh_pre) {
			ob_oh_pre_fqid = qman_fq_fqid(&n_if->tx_fqs[0]);
			break;
		}
	}
	if (!ob_oh_pre_fqid) {
		error(0, ENODEV, "FQID for OUTBOUND OH PRE SEC not found");
		return -ENODEV;
	}

	for (i = 0; i < sizeof(ob_rx_dists) / sizeof(ob_rx_dists[0]); i++) {
		memset(fmc_path, 0, sizeof(fmc_path));
		sprintf(fmc_path, "fm%d/port/MAC/%d/dist/%s",
				init.fm_idx, f_ob_rx->mac_idx, ob_rx_dists[i]);
		ret = set_dist_base_fqid(init.model, fmc_path, ob_oh_pre_fqid);
		if (ret < 0) {
			error(0, -ret, "Failed to update base FQID %d for %s",
					ob_oh_pre_fqid, ob_rx_dists[i]);
			return ret;
		}
	}

	return 0;
}

/* Do all library initialization that is dependent on a portal-enabled
 * USDPAA thread. Driver initialization happens before this, so we can
 * assume the drivers are already initialized. */
static int do_library_init(void)
{
	int ret;
	unsigned int loop;
	struct list_head *i;
	char fmc_path[64] = "";

	INIT_LIST_HEAD(&init.nfapi_init_data.ifs);

	for (loop = 0; loop < init.nfapi_init_data.netcfg->num_ethports; loop++) {
		ret = net_if_init(loop);
		if (ret) {
			return ret;
		}
	}

	list_for_each(i, &init.nfapi_init_data.ifs) {
		ret = net_if_rx_init((struct net_if *)i);
		if (ret) {
			return ret;
		}
	}

	ret = init_buffer_pools();
	if (ret) {
		return ret;
	}

	ret = update_ipsec_ob_default_fq();
	if (ret) {
		return ret;
	}

	/* execute PCD model */
	ret = fmc_execute(init.model);
	if (ret != E_OK) {
		fprintf(stderr, "error executing fmc model (%d)\n", ret);
		return ret;
	}

	/* get the pcd dev handle */
	memset(fmc_path, 0, sizeof(fmc_path));
	sprintf(fmc_path, "fm%d/pcd", init.fm_idx);
	init.nfapi_init_data.pcd_dev = fmc_get_handle(init.model, fmc_path);
	if (!init.nfapi_init_data.pcd_dev) {
		fprintf(stderr, "pcd dev cannot be null\n");
		return -ENODEV;
	}

	/* allocate memory for all caches */

	if (unlikely(NULL == mem_cache_init())) {
		fprintf(stderr, "Cache Creation error\n");
		return -ENOMEM;
	}

	gbl_init = &init.nfapi_init_data;

	ret = dpa_classif_lib_init();
	if (ret < 0) {
		fprintf(stderr, "dpa_classif_lib_init failed, err %d\n", ret);
		return ret;
	}

	/* Application specific initialization */
	if (init.is_ipsec) {
		ret = nf_ipsec_init();
		if (ret)
			return ret;
	}

	if (init.is_ipfwd) {
		ret = nf_ipfwd_init();
		if (ret)
			return ret;
	}

	return 0;
}

static int init_pool_channels(void)
{
	int i, ret;

	ret = qman_alloc_pool_range(&init.pchannels[0], NUM_POOL_CHANNELS, 1, 0);
	if (ret != NUM_POOL_CHANNELS)
		return -ENOMEM;

	for (i = 0; i < NUM_POOL_CHANNELS; i++)
		init.sdqcr |= QM_SDQCR_CHANNELS_POOL_CONV(init.pchannels[i]);

	return 0;
}

static void save_user_data(struct nf_user_data * data)
{
	if (data->ipsec_user_data) {
		struct nf_ipsec_user_data * src, * dst;

		init.is_ipsec = 1;
		src = data->ipsec_user_data;
		dst = &init.nfapi_init_data.ipsec.user_data;

		/* Copy array of fragmentation nodes */

		if (src->frag_nodes) {
			dst->n_frag_nodes = src->n_frag_nodes;
			memcpy(&dst->frag_nodes, src->frag_nodes,
				   src->n_frag_nodes *	sizeof(src->frag_nodes));
		}

		memcpy(dst, src, sizeof(struct nf_ipsec_user_data));
	}

	if (data->ipfwd_user_data) {
		struct nf_ipfwd_user_data * src, * dst;

		init.is_ipfwd = 1;
		src = data->ipfwd_user_data;
		dst = &init.nfapi_init_data.ipfwd.user_data;

		memcpy(dst, src, sizeof(struct nf_ipfwd_user_data));
	}
}

int nf_init(struct nf_user_data * user_data)
{
	int ret = 0;
	int calm_down = 16;
	cpu_set_t cpuset;
	const char *env_cfg, *env_pol, *env_pcd, *env_pdl, *env_swp;

	/* save the info provided by the user app */

	if (!user_data)
		return -1;
	save_user_data(user_data);

	/* Determine number of cores */

	init.ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (init.ncpus < 1) {
		fprintf(stderr, "Invalid number of cpus: %d\n", init.ncpus);
		return -1;
	}


	ret = of_init();
	if (ret) {
		fprintf(stderr, "of_init failed\n");
		return ret;
	}

	/* parse config XMLs */

	env_cfg = getenv(CFG_PATH);
	env_pol = getenv(POL_PATH);
	env_pdl = getenv(PDL_PATH);
	env_pcd = getenv(PCD_PATH);
	env_swp = getenv(SWP_PATH);

	init.nfapi_init_data.netcfg = usdpaa_netcfg_acquire(env_pol, env_cfg);
	dump_usdpaa_netcfg(init.nfapi_init_data.netcfg);
	if (!init.nfapi_init_data.netcfg) {
		fprintf(stderr, "FAIL: usdpaa_netcfg_acquire(%s,%s).\n",
				env_pol, env_cfg);
		goto err_of;
	}

	/* compile PCD model */

	init.model = malloc(sizeof(struct fmc_model_t));
	if (!init.model)
		goto err_netcfg;

	ret = fmc_compile(init.model,
			env_cfg, env_pcd, env_pdl, env_swp, 0x20, 0, NULL);
	if (ret) {
		fprintf(stderr,
			"error compiling fmc configuration (%d) : %s\n", ret,
			fmc_get_error());
		goto err_fmc;
	}

	/* save port info from the XML config */
	ret = parse_ipsec_config(env_cfg);
	if (ret) {
		fprintf(stderr, "Error parsing config XML\n");
		goto err_fmc;
	}

	ret = qman_global_init();
	if (ret) {
		fprintf(stderr, "Sched init: qman_global_init failed\n");
		goto err_fmc;
	}

	ret = bman_global_init();
	if (ret) {
		fprintf(stderr, "bman_global_init failed\n");
		goto err_fmc;
	}

	ret = init_pool_channels();
	if (ret) {
		fprintf(stderr, "error: no pool channels available\n");
		goto err_fmc;
	}

	dma_mem_generic = dma_mem_create(DMA_MAP_FLAG_ALLOC, NULL, DMA_MAP_SIZE);
	if (!dma_mem_generic)
		goto err_dma_mem;

	/* set CPU affinity */
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);

	/* Initialize thread/cpu-local portals */
	ret = bman_thread_init();
	if (ret) {
		error(0, ret, "Fail on bman_thread_init()");
		goto err_bman;
	}

	ret = qman_thread_init();
	if (ret) {
		error(0, ret, "Fail on qman_thread_init()");
		goto err_qman;
	}

	/* Initialise thread/cpu-local enqueue object */
	ret = qman_create_fq(1, QMAN_FQ_FLAG_NO_MODIFY, &local_fq);
	if (ret) {
		error(0, ret, "Error on qman_create_fq() for local fq");
		goto err_qman_fq;
	}

	/* Set the qman portal's SDQCR mask */
	qman_static_dequeue_add(init.sdqcr);

	ret = do_library_init();
	if (ret) {
		error(0, ret, "Error on library init");
		goto err_lib_init;
	}

	return 0;

err_lib_init:
	qman_static_dequeue_del(~(uint32_t)0);
err_qman_fq:
	while (calm_down--) {
		qman_poll_slow();
		qman_poll_dqrr(16);
	}
err_qman:
	qman_thread_finish();
err_bman:
	bman_thread_finish();
err_dma_mem:
	qman_release_pool_range(init.pchannels[0], NUM_POOL_CHANNELS);
err_fmc:
	if (init.model)
		free(init.model);
err_netcfg:
	usdpaa_netcfg_release(init.nfapi_init_data.netcfg);
err_of:
	of_finish();

	return -1;
}

void nf_finish(void)
{
	int calm_down = 16;

	do_library_finish();

	qman_static_dequeue_del(~(uint32_t)0);

	while (calm_down--) {
		qman_poll_slow();
		qman_poll_dqrr(16);
	}

	qman_thread_finish();

	bman_thread_finish();

	qman_release_pool_range(init.pchannels[0], NUM_POOL_CHANNELS);

	if (init.model)
		free(init.model);

	usdpaa_netcfg_release(init.nfapi_init_data.netcfg);

	of_finish();
}
