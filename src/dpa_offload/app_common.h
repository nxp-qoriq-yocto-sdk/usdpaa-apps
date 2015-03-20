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

#ifndef __APP_COMMON_H
#define __APP_COMMON_H

#include <stdbool.h>
#include <net/if.h>

#ifdef ENABLE_TRACE
#define TRACE printf
#else
#define TRACE(x, ...) do { ; } while(0)
#endif

enum ether_types {
	ETHER_TYPE_IPv4 = 0,
	ETHER_TYPE_IPv6,
	MAX_ETHER_TYPES
};

struct app_conf {
	/* inbound loopback set */
	bool ib_loop;
	/* Enable inbound policy verification */
	bool ib_policy_verification;
	/* Virtual inbound interface name */
	char vif[IFNAMSIZ];
	/* Virtual outbound interface name */
	char vof[IFNAMSIZ];
	/* IPsec interface name */
	char vipsec[IFNAMSIZ];
	/* Outer header TOS field */
	int outer_tos;
	/* enable inbound ECN tunneling*/
	bool ib_ecn;
	/* enable outbound ECN tunneling */
	bool ob_ecn;
};

extern struct app_conf app_conf;

#endif /* defined  __APP_COMMON_H */
