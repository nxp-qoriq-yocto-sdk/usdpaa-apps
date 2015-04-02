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

#ifndef __APP_SIZING_H
#define __APP_SIZING_H

#define NUM_POOL_CHANNELS		4
#define MAX_CACHELINE			64
#define SEC_DATA_OFF_BURST		1
#define SEC_ERA_5_DATA_OFF_BURST	3
#define NUM_TX_FQS_10G			2	/* 10G Port Tx FQ count */
#define NUM_TX_FQS_1G			2	/* 1G Port Tx FQ count */
#define NUM_TX_FQS_OFFLINE		2	/* Offline Port Tx FQ count */
#define NUM_TX_FQS_ONIC			1	/* ONIC Port Tx FQ count */
#define DMA_MAP_SIZE			0x8000000 /*128M*/
#define MAX_BPID			64

/*
 * Sizing info
 * FIXME: should they be here?
 */
#if defined P4080
#define NUM_SETS			2
#define NUM_WAYS			8
#elif defined B4860
#define NUM_SETS			8
#define NUM_WAYS			8
#elif defined B4420
#define NUM_SETS			8
#define NUM_WAYS			8
#else
#define NUM_SETS			2
#define NUM_WAYS			8
#endif
#define SETS				0
#define WAYS				1

/* Number of sets and ways per inbound pre-sec CC node type */
#define IPSEC_IN_SA_HASH_ENTRIES {					\
	[DPA_IPSEC_SA_IPV4][SETS] = NUM_SETS,				\
	[DPA_IPSEC_SA_IPV4][WAYS] = NUM_WAYS, 				\
	[DPA_IPSEC_SA_IPV4_NATT][SETS] = NUM_SETS,			\
	[DPA_IPSEC_SA_IPV4_NATT][WAYS] = NUM_WAYS,			\
	[DPA_IPSEC_SA_IPV6][SETS] = NUM_SETS,				\
	[DPA_IPSEC_SA_IPV6][WAYS] = NUM_WAYS,				\
}

/*
 * Max number of keys per outbound pre-sec CC node type
 * 0 - not used
 */
#define IPSEC_OUT_POL_CC_NODE_KEYS {					\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_TCP_IPV4 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_TCP_IPV6 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_UDP_IPV4 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_UDP_IPV6 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_ICMP_IPV4 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_ICMP_IPV6 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_SCTP_IPV4 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_SCTP_IPV6 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_ANY_IPV4 */				\
	NUM_SETS * NUM_WAYS,						\
		/* DPA_IPSEC_PROTO_ANY_IPV6 */				\
}

/* Key sizes per inbound pre-sec CC node type */
#define IPSEC_PRE_DEC_TBL_KEY_SIZE {					\
	/* IPV4 SA */							\
	(DPA_OFFLD_IPv4_ADDR_LEN_BYTES +				\
	IP_PROTO_FIELD_LEN +						\
	ESP_SPI_FIELD_LEN),						\
	/* IPV4 SA w/ NATT*/						\
	(DPA_OFFLD_IPv4_ADDR_LEN_BYTES +				\
	IP_PROTO_FIELD_LEN +						\
	2 * PORT_FIELD_LEN +						\
	ESP_SPI_FIELD_LEN),						\
	/* IPV6 SA */							\
	(DPA_OFFLD_IPv6_ADDR_LEN_BYTES +				\
	IP_PROTO_FIELD_LEN +						\
	ESP_SPI_FIELD_LEN)						\
	}

/*
 * Key sizes per outbound pre-sec CC node type
 * 0 - not used
 */
#define IPSEC_OUT_PRE_ENC_TBL_KEY_SIZE \
	{ \
	(2 * DPA_OFFLD_IPv4_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN +	\
	 2 * PORT_FIELD_LEN),						\
	(2 * DPA_OFFLD_IPv6_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN +	\
	 2 * PORT_FIELD_LEN),						\
	(2 * DPA_OFFLD_IPv4_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN +	\
	 2 * PORT_FIELD_LEN),						\
	(2 * DPA_OFFLD_IPv6_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN +	\
	 2 * PORT_FIELD_LEN),						\
	(2 * DPA_OFFLD_IPv4_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN),	\
	(2 * DPA_OFFLD_IPv6_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN),	\
	(2 * DPA_OFFLD_IPv4_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN +	\
	 2 * PORT_FIELD_LEN),						\
	(2 * DPA_OFFLD_IPv6_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN +	\
	 2 * PORT_FIELD_LEN),						\
	(2 * DPA_OFFLD_IPv4_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN +	\
	 2 * PORT_FIELD_LEN),						\
	(2 * DPA_OFFLD_IPv6_ADDR_LEN_BYTES + IP_PROTO_FIELD_LEN +	\
	 2 * PORT_FIELD_LEN)						\
	}

/* Packet fields for outbound pre-sec traffic selector */
#define IPSEC_OUT_POL_TCPUDP_KEY_FIELDS					\
	(DPA_IPSEC_KEY_FIELD_SIP |					\
	DPA_IPSEC_KEY_FIELD_DIP |					\
	DPA_IPSEC_KEY_FIELD_PROTO |					\
	DPA_IPSEC_KEY_FIELD_SPORT |					\
	DPA_IPSEC_KEY_FIELD_DPORT)

#define IPSEC_OUT_POL_ICMP_KEY_FIELDS					\
	(DPA_IPSEC_KEY_FIELD_SIP |					\
	DPA_IPSEC_KEY_FIELD_DIP |					\
	DPA_IPSEC_KEY_FIELD_PROTO)

#define IN_SA_PCD_HASH_OFF	0
#define IPSEC_START_IN_FLOW_ID	0

#define PRIORITY_2TX		4		/* Consumed by Fman */
#define PRIORITY_2DROP		3		/* Error/default/etc */
#define PRIORITY_2FWD		4		/* rx-hash */

#define TX_FQ_NO_BUF_DEALLOC	0x00000001	/* Disable buffer deallocation*/
#define TX_FQ_NO_CHECKSUM	0x00000002	/* Disable checksum */
#define TX_FQ_SET_OPCODE11	0x00000004
#define CPU_SPIN_BACKOFF_CYCLES	512

#ifdef RX_1G_PREFERINCACHE
#define RX_1G_PIC 1
#else
#define RX_1G_PIC 0
#endif
#ifdef RX_10G_PREFERINCACHE
#define RX_10G_PIC 1
#else
#define RX_10G_PIC 0
#endif
#ifdef _2FWD_RX_OFFLINE_PREFERINCACHE
#define RX_OFFLINE_PIC 1
#else
#define RX_OFFLINE_PIC 0
#endif
#ifdef RX_ONIC_PREFERINCACHE
#define RX_ONIC_PIC 1
#else
#define RX_ONIC_PIC 0
#endif

#endif /* defined __APP_SIZING_H */
