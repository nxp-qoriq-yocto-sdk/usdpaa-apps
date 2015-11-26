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

#ifndef __XFRM_EVENTS_H
#define __XFRM_EVENTS_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/xfrm.h>
#include <compat.h>

#include "common_nfapi.h"
#include <ipsec_nfapi.h>

struct nf_pol {
	 /* link in in/out policies list */
	struct list_head list;
	/* xfrm policy information */
	struct xfrm_userpolicy_info xfrm_pol_info;
	/* Policy id required when perform remove */
	uint32_t policy_id;
	/* Direction required when perform remove */
	enum nf_ipsec_direction dir;
	/* IPSec NF API policy parameters */
	struct nf_ipsec_policy pol_params;
	/* matching SA src address */
	xfrm_address_t sa_saddr;
	 /* matching SA dest address*/
	xfrm_address_t sa_daddr;
	/* matching SA family */
	int sa_family;
	/* optional fragmentation manip descriptor */
	int manip_desc;
};

struct nf_sa {
	/* link in SADB */
	struct list_head list;
	/* xfrm sa information */
	struct xfrm_usersa_info xfrm_sa_info;
	/* NAT-T info */
	struct xfrm_encap_tmpl encap;
	/* SPI required when perform remove */
	uint32_t spi;
	/* Protocol required when perform remove */
	uint8_t protocol;
	/* IP Destination required when perform remove */
	struct nf_ip_addr dest_ip;
	/* IPSec NF API sa parameters */
	struct nf_ipsec_sa sa_params;
	/* policies list for inbound sa */
	struct list_head in_pols;
	/* policies list for outbound sa */
	struct list_head out_pols;
	/* parent sa used in rekeying process */
	struct nf_sa *parent_sa;
};

extern struct list_head nf_sa_list;

int setup_xfrm_msg_loop(int dpa_ipsec_id);
int teardown_xfrm_msg_loop(void);
void dump_xfrm_sa_info(struct xfrm_usersa_info *sa_info);

#endif /* __XFRM_EVENTS_H */
