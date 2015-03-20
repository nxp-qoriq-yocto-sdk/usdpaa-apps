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

#ifndef __NF_INIT_H
#define __NF_INIT_H

#include <stdint.h>
#include <fmc.h>
#include <compat.h>
#include <fman.h>
#include <fsl_bman.h>
#include <usdpaa_netcfg.h>

#include "fsl_dpa_ipsec.h"

#include "app_sizing.h"
#include "init_nfapi.h"

/* XML config parser */
#define CFG_FMAN_NODE			("engine")
#define CFG_FMAN_NA_name		("name")
#define CFG_PORT_NODE			("port")
#define CFG_PORT_NA_type		("type")
#define CFG_PORT_NA_number		("number")
#define CFG_PORT_NA_policy		("policy")
#define CFG_OB_POLICY			("ob_rx_policy")
#define CFG_IB_POLICY			("ib_rx_policy")
#define CFG_IB_OH_POLICY		("ib_oh_post_policy")
#define CFG_OB_OH_PRE_POLICY		("ob_oh_pre_policy")
#define CFG_OB_OH_POST_POLICY		("ob_oh_post_policy")

/*
 * Worker threads
 * Each thread is represented by a "worker" struct. It will exit when 'quit' is
 * set non-zero. The thread for 'cpu==0' will perform global init and set
 * 'init_done' once completed.
 */
struct worker {
	pthread_t id;
	volatile int quit;
	int cpu;
	int init_done;
};

#define WORKER_SLOWPOLL_BUSY 4
#define WORKER_SLOWPOLL_IDLE 400
#define WORKER_FASTPOLL_DQRR 16

/* Interfaces management */
struct net_if_admin {
	int idx;
	struct qman_fq fq;
};

/* Each "rx_hash" (PCD) FQ */
struct net_if_rx {
	struct qman_fq fq;
	/* Each Rx FQ is "pre-mapped" to a Tx FQ. Eg. if there are 32 Rx FQs and
	 * 2 Tx FQs for each interface, then each Tx FQ will be reflecting
	 * frames from 16 Rx FQs. */
	uint32_t tx_fqid;
#ifdef ORDER_RESTORATION
		/* Rather than embedding a whole ORP object, we embed only the
		 * ORP FQ object so that it takes less (stashable) space. */
		struct qman_fq *orp_fq;
#endif
};

/* Each PCD FQ-range within an interface is represented by one of these */
struct net_if_rx_fqrange {
	struct net_if_rx * rx;
	unsigned int rx_count;
	struct list_head list;
};

struct nf_user_data {
	struct nf_ipsec_user_data *ipsec_user_data;
	struct nf_ipfwd_user_data *ipfwd_user_data;
};

struct app_init_data {
	struct nf_init_data nfapi_init_data;
	bool is_ipsec;
	bool is_ipfwd;
	uint8_t ncpus;
	uint8_t fm_idx;
	struct fmc_model_t *model;
	/* The dynamically allocated pool-channels, and the iterator index that loops
	 * around them binding Rx FQs to them in a round-robin fashion. */
	uint32_t pchannel_idx;
	uint32_t pchannels[NUM_POOL_CHANNELS];
	/* The SDQCR mask to use (computed from pchannels) */
	uint32_t sdqcr;
	struct bman_pool *pool[MAX_BPID];
};

#ifdef ENABLE_TRACE

#define IP4_ROUTE_TABLES		2
#define IP6_ROUTE_TABLES		2

extern t_Handle ob_pre_cc_node[DPA_IPSEC_MAX_SUPPORTED_PROTOS];
extern t_Handle ib_pre_cc_node[DPA_IPSEC_MAX_SA_TYPE];
extern t_Handle ip4_route_cc_node[IP4_ROUTE_TABLES];
extern t_Handle ip6_route_cc_node[IP6_ROUTE_TABLES];
#endif /* ENABLE_TRACE */

int nf_init(struct nf_user_data *user_data);

void nf_finish(void);

#endif /* defined __NF_INIT_H */
