/**
 * \file
 * \brief Derived from ipfwd.c
 * Copyright (C) 2012 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lpm-ipfwd.h"

#include "ppam_if.h"
#include <ppac_interface.h>

#include "net/annotations.h"
#include "ethernet/eth.h"
#include "arp/arp.h"
#include "ip/ip_protos.h"
#include "ip/ip_handler.h"
#include "ip/ip_appconf.h"
#include "ip/fib.h"
#include <mem_cache.h>

#include <mqueue.h>
#include <netinet/if_ether.h>

/** \brief	Holds all IP-related data structures */
struct ip_stack_t {
	struct ip_statistics_t *ip_stats;	/**< IPv4 Statistics */
	struct ip_protos_t protos;		/**< Protocol Handler */
	struct neigh_table_t arp_table;		/**< ARP Table */
};

struct ip_stack_t stack;
static mqd_t mq_fd_rcv = -1, mq_fd_snd = -1;
static struct sigevent notification;


int is_iface_ip(in_addr_t addr)
{
	const struct ppac_interface *i;

	list_for_each_entry(i, &ifs, node)
		if (i->ppam_data.addr == addr)
			return 0;

	return -ENXIO;
}

struct ppac_interface *ipfwd_get_iface_for_ip(in_addr_t addr)
{
	struct ppac_interface *i;

	list_for_each_entry(i, &ifs, node)
		if ((i->ppam_data.addr & i->ppam_data.mask) ==
		    (addr & i->ppam_data.mask))
			return i;

	return NULL;
}

/**
 \brief Adds a new Route Cache entry
 \param[out] app_ctrl_route_info contains Route parameters
 \return Integer status
 */
static int ipfwd_add_route(const struct app_ctrl_op_info *route_info)
{
	in_addr_t gw_ipaddr = route_info->ip_info.gw_ipaddr;
	uint32_t fib_cnt, mask, daddr;
	uint32_t i;
	nh_action_t act;
	u16 port;
	struct neigh_t *neighbor;

	pr_debug("ipfwd_add_route: Enter\n");
	fib_cnt = route_info->ip_info.fib_cnt;
	mask = route_info->ip_info.mask;
	daddr = route_info->ip_info.dst_ipaddr;
	for (i = 0; i < fib_cnt; i++) {
		neighbor = neigh_lookup(&stack.arp_table,
				gw_ipaddr, stack.arp_table.proto_len);
		if (neighbor == NULL) {
			pr_info("neighbour NULL\n");
			return -1;
		}
		act = NH_FWD;
		port = 1;
		fib_add_route(daddr + i, mask, gw_ipaddr, port, act, neighbor);
	}
	pr_debug("ipfwd_add_route: Exit\n");
	return 0;
}

/**
 \brief Deletes an entry in FIB table
 \param[out] app_ctrl_route_info contains Route parameters
 \return Integer status
 */
static int ipfwd_del_route(const struct app_ctrl_op_info *route_info)
{
	pr_info("ipfwd_del_route: TBD\n");
	return 0;
}

/**
 \brief Adds a new Arp Cache entry
 \param[out] app_ctrl_route_info contains ARP parameters
 \return Integer status
 */
static int ipfwd_add_arp(const struct app_ctrl_op_info *route_info)
{
	in_addr_t ip_addr = route_info->ip_info.src_ipaddr;
	struct ppac_interface *dev = NULL;
	struct neigh_t *n;

#if (LOG_LEVEL > 3)
	uint8_t *ip = (typeof(ip))&ip_addr;
	pr_debug("ipfwd_add_arp: Enter\n");

	pr_debug("IP = %d.%d.%d.%d ; MAC ="ETH_MAC_PRINTF_FMT"\n",
		 ip[0], ip[1], ip[2], ip[3],
		 ETH_MAC_PRINTF_ARGS(&route_info->ip_info.mac_addr));
#endif

	n = neigh_lookup(&stack.arp_table, ip_addr, stack.arp_table.proto_len);

	if (n == NULL) {
		pr_debug
		    ("%s: Could not find neighbor entry for link-local addr\n",
		     __func__);

		dev = ipfwd_get_iface_for_ip(ip_addr);
		if (dev == NULL) {
			pr_debug("ipfwd_add_arp: Exit: Failed\n");
			return -1;
		}

		n = neigh_create(&stack.arp_table);
		if (unlikely(!n)) {
			pr_debug("ipfwd_add_arp: Exit: Failed\n");
			return -1;
		}
		if (NULL == neigh_init(&stack.arp_table, n, dev, &ip_addr)) {
			pr_err("ipfwd_add_arp: Exit: Failed\n");
			mutex_destroy(&n->wlock);
			return -1;
		}

		if (false == neigh_add(&stack.arp_table, n)) {
			pr_err("ipfwd_add_arp: Exit: Failed\n");
			mutex_destroy(&n->wlock);
			return -1;
		}
	} else {
		n->neigh_state = NEIGH_STATE_UNKNOWN;
		if (route_info->ip_info.replace_entry) {
			if (false == neigh_replace(&stack.arp_table, n)) {
				pr_err("ipfwd_add_arp: Exit: Failed\n");
				return -1;
			}
		}
	}
	/* Update ARP cache entry */
	if (NULL == neigh_update(n,
			route_info->ip_info.mac_addr.ether_addr_octet,
			NEIGH_STATE_PERMANENT)) {
		pr_err("ipfwd_add_arp: Exit: Failed\n");
		mutex_destroy(&n->wlock);
		return -1;
	}

	pr_debug("ipfwd_add_arp: Exit\n");
	return 0;
}

/**
 \brief Deletes an Arp Cache entry
 \param[out] app_ctrl_route_info contains ARP parameters
 \return Integer status
 */
static int ipfwd_del_arp(const struct app_ctrl_op_info *route_info)
{
	struct neigh_t *neighbor = NULL;
	pr_debug("ipfwd_del_arp: Enter\n");

	/*
	 ** Do a Neighbour LookUp for the entry to be deleted
	 */
	neighbor = neigh_lookup(&stack.arp_table,
				route_info->ip_info.src_ipaddr,
				stack.arp_table.proto_len);
	if (neighbor == NULL) {
		pr_err
		    ("Could not find neighbor entry for link-local address\n");
		return -1;
	}

	/*
	 ** Find out if anyone is using this entry
	 */
	if (*(neighbor->refcnt) != 0) {
		pr_err
		    ("Could not delete neighbor entry as it is being used\n");
		return -1;
	}

	/*
	 ** Delete the ARP Entry
	 */
	if (false == neigh_remove(&stack.arp_table,
				  route_info->ip_info.src_ipaddr,
				  stack.arp_table.proto_len)) {
		pr_err("Could not delete neighbor entry\n");
		return -1;
	}

	pr_debug("ipfwd_del_arp: Exit\n");
	return 0;
}

/**
 \brief Show Interfaces
 \param[out] app_ctrl_route_info contains intf parameters
 \return Integer status
 */
static int ipfwd_show_intf(const struct app_ctrl_op_info *route_info)
{
	const struct fman_if *fif;
	const struct fm_eth_port_cfg *port;
	int i, iface, loop;

	for (loop = 0; loop < netcfg->num_ethports; loop++) {
		port = &netcfg->port_cfg[loop];
		fif = port->fman_if;
		if (fif->mac_type == fman_mac_less) {
			printf("MACLESS Interface:\n name : %s\n",
				fif->macless_info.macless_name);
		} else {
			iface = (fif->mac_type == fman_mac_1g ? 0 : 80)
				+ fif->mac_idx;
			i = fif->fman_idx * 100 + iface;
			printf("FMAN Interface number: %d\n, "
				"PortID=%d:%d is FMan interface node "
				"with MAC Address "ETH_MAC_PRINTF_FMT"\n",
				i, fif->fman_idx, iface,
				ETH_MAC_PRINTF_ARGS(&fif->mac_addr));
		}
	}
	return 0;
}

/**
 \brief Change Interface Configuration
 \param[out] app_ctrl_route_info contains intf config parameters
 \return Integer status
 */
static int ipfwd_conf_intf(const struct app_ctrl_op_info *route_info)
{
	struct ppac_interface *i;
	struct ppam_interface *p;
	const struct fman_if *fif;
	uint16_t addr_hi;
	int _errno = 1, node, ifnum;
	const char *str = "mac interface";
	const char *ifname;
	int is_macless = 0;

	pr_debug("%s: Enter\n", __func__);

	addr_hi = ETHERNET_ADDR_MAGIC;
	ifname = route_info->ip_info.intf_conf.ifname;
	ifnum = route_info->ip_info.intf_conf.ifnum;
	if (strncmp(str, ifname, strlen(ifname)) != 0)
		is_macless = 1;
	list_for_each_entry(i, &ifs, node) {
		p = &i->ppam_data;
		fif = i->port_cfg->fman_if;
		if (is_macless) {
			if (fif->mac_type != fman_mac_less)
				continue;
			if (strcmp(ifname, p->ifname) != 0)
				continue;
			p->addr = route_info->ip_info.intf_conf.ip_addr;
			pr_info("IPADDR assigned = 0x%x to MACLESS intf %s\n",
				p->addr, fif->macless_info.macless_name);
			_errno = 0;
			break;
		} else {
			if (p->ifnum != ifnum)
				continue;
			p->addr = route_info->ip_info.intf_conf.ip_addr;
			pr_info("IPADDR assigned = 0x%x to interface num %d\n",
				p->addr, p->ifnum);
			for (node = 0; node < ARRAY_SIZE(p->local_nodes);
				 node++) {
				p->local_nodes[node].ip = p->addr + 1 + node;
				memcpy(&p->local_nodes[node].mac, &addr_hi,
					sizeof(addr_hi));
				memcpy(p->local_nodes[node].mac.ether_addr_octet
					+ sizeof(addr_hi),
					&p->local_nodes[node].ip,
					sizeof(p->local_nodes[node].ip));
			}
			_errno = 0;
			break;
		}
	}
	if (_errno) {
		if (is_macless) {
			pr_info("MACLESS Interface %s is not an enabled interface\n",
				 route_info->ip_info.intf_conf.ifname);
		} else {
			pr_info("Interface number %d is not an enabled interface\n",
			 ifnum);
		}
	}

	pr_debug("%s: Exit\n", __func__);
	return _errno;
}

/**
 \brief Initialize IPSec Statistics
 \param[in] void
 \param[out] struct ip_statistics_t *
 */
static struct ip_statistics_t *ipfwd_stats_init(void)
{
	int _errno;
	void *ip_stats;

	_errno = posix_memalign(&ip_stats,
				__alignof__(struct ip_statistics_t),
				sizeof(struct ip_statistics_t));
	return unlikely(_errno < 0) ? NULL : ip_stats;
}

/**
 \brief Initialize IP Stack
 \param[in] struct ip_stack_t * IPFwd Stack pointer
 \param[out] Return Status
 */
static int initialize_ip_stack(struct ip_stack_t *ip_stack)
{
	int _errno;

	_errno = arp_table_init(&ip_stack->arp_table);

	_errno = neigh_table_init(&ip_stack->arp_table);
	if (unlikely(_errno < 0)) {
		pr_err("Failed to init ARP Table\n");
		return _errno;
	}
	_errno = fib_init();
	if (unlikely(_errno < 0)) {
		pr_err("Failed in fib initialized\n");
		return _errno;
	}
	_errno = ip_protos_init(&ip_stack->protos);

	ip_stack->ip_stats = ipfwd_stats_init();
	if (unlikely(ip_stack->ip_stats == NULL)) {
		pr_err("Unable to allocate ip stats structure for stack\n");
		return -ENOMEM;
	}
	memset(ip_stack->ip_stats, 0, sizeof(*ip_stack->ip_stats));

	pr_debug("IP Statistics initialized\n");
	return 0;
}

/**
 \brief Message handler for message coming from Control plane
 \param[in] app_ctrl_op_info contains SA parameters
 \return NULL
*/
static void process_req_from_mq(struct app_ctrl_op_info *sa_info)
{
	int32_t s32Result = 0;
	sa_info->result = IPC_CTRL_RSLT_FAILURE;

	pr_debug("process_req_from_mq: Enter\n");
	switch (sa_info->msg_type) {
	case IPC_CTRL_CMD_TYPE_ROUTE_ADD:
		s32Result = ipfwd_add_route(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ROUTE_DEL:
		s32Result = ipfwd_del_route(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ARP_ADD:
		s32Result = ipfwd_add_arp(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ARP_DEL:
		s32Result = ipfwd_del_arp(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_INTF_CONF_CHNG:
		s32Result = ipfwd_conf_intf(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_SHOW_INTF:
		s32Result = ipfwd_show_intf(sa_info);
		break;

	default:
		break;
	}

	if (s32Result == 0)
		sa_info->result = IPC_CTRL_RSLT_SUCCESSFULL;
	else
		pr_err("%s: CP Request can't be handled\n", __func__);

	pr_debug("process_req_from_mq: Exit\n");
	return;
}

int receive_data(mqd_t mqdes)
{
	ssize_t size;
	struct app_ctrl_op_info *ip_info = NULL;
	struct mq_attr attr;
	int _err = 0;

	ip_info = (struct app_ctrl_op_info *)malloc
			(sizeof(struct app_ctrl_op_info));
	if (unlikely(!ip_info)) {
		pr_err("%s: %dError getting mem for ip_info\n",
			 __FILE__, __LINE__);
		return -ENOMEM;
	}
	memset(ip_info, 0, sizeof(struct app_ctrl_op_info));

	_err = mq_getattr(mqdes, &attr);
	if (unlikely(_err)) {
		pr_err("%s: %dError getting MQ attributes\n",
			 __FILE__, __LINE__);
		goto error;
	}
	size = mq_receive(mqdes, (char *)ip_info, attr.mq_msgsize, 0);
	if (unlikely(size == -1)) {
		pr_err("%s: %dRcv msgque error\n", __FILE__, __LINE__);
		goto error;
	}
	process_req_from_mq(ip_info);
	/* Sending result to application configurator tool */
	_err = mq_send(mq_fd_snd, (const char *)ip_info,
			sizeof(struct app_ctrl_op_info), 10);
	if (unlikely(_err != 0)) {
		pr_err("%s: %d Error in sending msg on MQ\n",
			__FILE__, __LINE__);
		goto error;
	}

	return 0;
error:
	free(ip_info);
	return _err;
}

static void mq_handler(union sigval sval)
{
	pr_debug("mq_handler called %d\n", sval.sival_int);

	receive_data(mq_fd_rcv);
	mq_notify(mq_fd_rcv, &notification);
}

static int create_mq(void)
{
	struct mq_attr attr_snd, attr_rcv;
	int _err = 0, ret;
	char name[MAX_MQ_NAME_LEN];

	pr_debug("Create mq: Enter\n");
	if ((mq_fd_snd != -1) || (mq_fd_rcv != -1))
		return 0;
	memset(&attr_snd, 0, sizeof(attr_snd));

	/* Create message queue to send the response */
	attr_snd.mq_maxmsg = MAX_MQ_NAME_LEN;
	attr_snd.mq_msgsize = 8192;
	snprintf(name, MAX_MQ_NAME_LEN, "/mq_snd_%d", getpid());
	printf("Message queue to send: %s\n", name);
	mq_fd_snd = mq_open(name, O_CREAT | O_WRONLY,
				(S_IRWXU | S_IRWXG | S_IRWXO), &attr_snd);
	if (mq_fd_snd == -1) {
		pr_err("%s: %dError opening SND MQ\n",
				__FILE__, __LINE__);
		_err = -errno;
		goto error;
	}

	memset(&attr_rcv, 0, sizeof(attr_rcv));

	snprintf(name, MAX_MQ_NAME_LEN, "/mq_rcv_%d", getpid());
	printf("Message queue to receive: %s\n", name);
	/* Create message queue to read the message */
	attr_rcv.mq_maxmsg = MAX_MQ_NAME_LEN;
	attr_rcv.mq_msgsize = 8192;
	mq_fd_rcv = mq_open(name, O_CREAT | O_RDONLY,
				 (S_IRWXU | S_IRWXG | S_IRWXO), &attr_rcv);
	if (mq_fd_rcv == -1) {
		pr_err("%s: %dError opening RCV MQ\n",
				 __FILE__, __LINE__);
		_err = -errno;
		goto error;
	}

	notification.sigev_notify = SIGEV_THREAD;
	notification.sigev_notify_function = mq_handler;
	notification.sigev_value.sival_ptr = &mq_fd_rcv;
	notification.sigev_notify_attributes = NULL;
	ret =  mq_notify(mq_fd_rcv, &notification);
	if (ret) {
		pr_err("%s: %dError in mq_notify call\n",
				 __FILE__, __LINE__);
		_err = -errno;
		goto error;
	}
	pr_debug("Create mq: Exit\n");
	return 0;
error:
	if (mq_fd_snd)
		mq_close(mq_fd_snd);

	if (mq_fd_rcv)
		mq_close(mq_fd_rcv);

	return _err;
}

int ppam_init(void)
{
	int _errno;

	printf("%s starting\n", program_invocation_short_name);

	/* Initializes a soft cache of buffers */
	if (unlikely(NULL == mem_cache_init())) {
		pr_err("Cache Creation error\n");
		return -ENOMEM;
	}
	/* Initializes IP stack*/
	_errno = initialize_ip_stack(&stack);
	if (unlikely(_errno < 0)) {
		pr_err("Error Initializing IP Stack\n");
		return _errno;
	}

	/* Create Message queues to send and receive */
	_errno = create_mq();
	if (unlikely(_errno < 0)) {
		pr_err("Error in creating message queues\n");
		return _errno;
	}

	return 0;
}

void ppam_finish(void)
{
	char name[MAX_MQ_NAME_LEN];

	TRACE("closing snd and rcv message queues\n");

	if (mq_fd_snd >= 0) {
		if (mq_close(mq_fd_snd) == -1)
			error(0, errno, "%s():mq_close send", __func__);
		mq_fd_snd = -1;
		snprintf(name, MAX_MQ_NAME_LEN, "/mq_snd_%d", getpid());
		if (mq_unlink(name) == -1)
			error(0, errno, "%s():mq_unlink send", __func__);
	}
	if (mq_fd_rcv >= 0) {
		if (mq_close(mq_fd_rcv) == -1)
			error(0, errno, "%s():mq_close rcv", __func__);
		mq_fd_rcv = -1;
		snprintf(name, MAX_MQ_NAME_LEN, "/mq_rcv_%d", getpid());
		if (mq_unlink(name) == -1)
			error(0, errno, "%s():mq_unlink rcv", __func__);
	}
}

static int ppam_interface_init(struct ppam_interface *p,
			       const struct fm_eth_port_cfg *cfg,
			       unsigned int num_tx_fqs,
			       uint32_t *flags __maybe_unused)
{
	int iface;
	const struct fman_if *fif;

	fif = cfg->fman_if;

	if (fif->mac_type == fman_mac_less) {
		p->num_tx_fqids = num_tx_fqs;
		p->ifname = fif->macless_info.macless_name;
		p->tx_fqids = malloc(p->num_tx_fqids * sizeof(*p->tx_fqids));
		if (unlikely(p->tx_fqids == 0))
			return -ENOMEM;
		return 0;
	}

	iface = (fif->mac_type == fman_mac_1g ? 0 : 80) + fif->mac_idx;
	p->ifnum = fif->fman_idx * 100 + iface;
	p->mtu = ETHERMTU;
	p->header_len = ETHER_HDR_LEN;
	p->mask = IN_CLASSC_NET;

	p->num_tx_fqids = num_tx_fqs;
	p->tx_fqids = malloc(p->num_tx_fqids * sizeof(*p->tx_fqids));
	if (unlikely(p->tx_fqids == 0))
		return -ENOMEM;

	eth_setup(p);

	if (fif->mac_type == fman_mac_1g)
		printf("Configured 1G port @ FMAN:%d, MAC:%d as IF_IDX:%d\n",
			fif->fman_idx, fif->mac_idx, p->ifnum);
	if (fif->mac_type == fman_mac_10g)
		printf("Configured 10G port @ FMAN:%d, MAC:%d as IF_IDX:%d\n",
			fif->fman_idx, fif->mac_idx, p->ifnum);

	return 0;
}
static void ppam_interface_finish(struct ppam_interface *p)
{
	free(p->tx_fqids);
}
static void ppam_interface_tx_fqid(struct ppam_interface *p, unsigned idx,
				   uint32_t fqid)
{
	p->tx_fqids[idx] = fqid;
}
static int ppam_rx_error_init(struct ppam_rx_error *p,
			      struct ppam_interface *_if,
			      struct qm_fqd_stashing *stash_opts)
{
	p->stats = stack.ip_stats;
	p->protos = &stack.protos;

	return 0;
}
static void ppam_rx_error_finish(struct ppam_rx_error *p,
				 struct ppam_interface *_if)
{
}
static inline void ppam_rx_error_cb(struct ppam_rx_error *p,
				    struct ppam_interface *_if,
				    const struct qm_dqrr_entry *dqrr)
{
	ppac_drop_frame(&dqrr->fd);
}
static int ppam_rx_default_init(struct ppam_rx_default *p,
				struct ppam_interface *_if,
				unsigned idx,
				struct qm_fqd_stashing *stash_opts)
{
	struct ppac_interface *c_if = container_of(_if, struct ppac_interface,
						   ppam_data);
	const struct fman_if *fif = c_if->port_cfg->fman_if;
	p->stats = stack.ip_stats;
	p->protos = &stack.protos;
	p->tx_fqid = _if->tx_fqids[idx % _if->num_tx_fqids];
	if (fif->mac_type == fman_mac_less)
		p->is_macless = 1;

	TRACE("Mapping Rx FQ %p:%d --> Tx FQID %d\n", p, idx, p->tx_fqid);

	return 0;
}
static void ppam_rx_default_finish(struct ppam_rx_default *p,
				   struct ppam_interface *_if)
{
}
/* Swap 6-byte MAC headers */
static inline void ether_header_swap(struct ether_header *prot_eth)
{
	register u32 a, b, c;
	u32 *overlay = (u32 *)prot_eth;
	a = overlay[0];
	b = overlay[1];
	c = overlay[2];
	overlay[0] = (b << 16) | (c >> 16);
	overlay[1] = (c << 16) | (a >> 16);
	overlay[2] = (a << 16) | (b >> 16);
}

static inline void ppam_rx_default_cb(struct ppam_rx_default *p,
				      struct ppam_interface *_if,
				      const struct qm_dqrr_entry *dqrr)
{
	struct annotations_t *notes;
	struct ether_header *eth_hdr;
	const struct qm_fd *fd = &dqrr->fd;

	BUG_ON(fd->format != qm_fd_contig);
	notes = __dma_mem_ptov(qm_fd_addr(fd));
	eth_hdr = (void *)notes + dqrr->fd.offset;
	switch (eth_hdr->ether_type) {
	case ETHERTYPE_IP:
		TRACE("	       -> it's ETHERTYPE_IP!\n");
		{
		/* Send ping reply only for MAC-less else drop the frame */
		if (p->is_macless == 1) {
			struct iphdr *iphdr = (typeof(iphdr))(eth_hdr + 1);
			__be32 tmp;
			/* switch ipv4 src/dst addresses */
			tmp = iphdr->daddr;
			iphdr->daddr = iphdr->saddr;
			iphdr->saddr = tmp;
			/* switch ethernet src/dest MAC addresses */
			ether_header_swap(eth_hdr);
			ppac_send_frame(p->tx_fqid, fd);
		} else
			break;
		}
		return;
	case ETHERTYPE_ARP:
		TRACE("	       -> it's ETHERTYPE_ARP!\n");
		{
		notes->dqrr = dqrr;
		arp_handler(_if, notes, eth_hdr);
		}
		return;
	default:
		TRACE("	       -> it's UNKNOWN (!!) type 0x%04x\n",
			eth_hdr->ether_type);
		TRACE("		  -> dropping unknown packet\n");
	}
	ppac_drop_frame(fd);
}
static int ppam_tx_error_init(struct ppam_tx_error *p,
			      struct ppam_interface *_if,
			      struct qm_fqd_stashing *stash_opts)
{
	return 0;
}
static void ppam_tx_error_finish(struct ppam_tx_error *p,
				 struct ppam_interface *_if)
{
}
static inline void ppam_tx_error_cb(struct ppam_tx_error *p,
				    struct ppam_interface *_if,
				    const struct qm_dqrr_entry *dqrr)
{
	ppac_drop_frame(&dqrr->fd);
}
static int ppam_tx_confirm_init(struct ppam_tx_confirm *p,
				struct ppam_interface *_if,
				struct qm_fqd_stashing *stash_opts)
{
	return 0;
}
static void ppam_tx_confirm_finish(struct ppam_tx_confirm *p,
				   struct ppam_interface *_if)
{
}
static inline void ppam_tx_confirm_cb(struct ppam_tx_confirm *p,
				      struct ppam_interface *_if,
				      const struct qm_dqrr_entry *dqrr)
{
	ppac_drop_frame(&dqrr->fd);
}

static int ppam_rx_hash_init(struct ppam_rx_hash *p,
			     struct ppam_interface *_if,
			     unsigned idx, struct qm_fqd_stashing *stash_opts)
{
	p->stats = stack.ip_stats;
	p->protos = &stack.protos;

	/* Override defaults, enable 1 CL of annotation stashing */
	stash_opts->annotation_cl = (sizeof(struct annotations_t)
					+ L1_CACHE_BYTES - 1) /	L1_CACHE_BYTES;

	return 0;
}
static void ppam_rx_hash_finish(struct ppam_rx_hash *p,
				struct ppam_interface *_if,
				unsigned idx)
{
}

static inline void ppam_rx_hash_cb(struct ppam_rx_hash *p,
				   const struct qm_dqrr_entry *dqrr)
{
	struct annotations_t *notes;
	void *data;
	switch (dqrr->fd.format) {
	case qm_fd_contig:
		notes = __dma_mem_ptov(qm_fd_addr(&dqrr->fd));
		data = (void *)notes + dqrr->fd.offset;
		break;
	default:
		pr_err("Unsupported format packet came\n");
		return;
	}
	notes->dqrr = dqrr;

	ip_handler(p, notes, data);
}

#include <ppac.c>

struct ppam_arguments {
};

struct ppam_arguments ppam_args;

const char ppam_doc[] = "IP forwarding";

static const struct argp_option argp_opts[] = {
	{}
};

const struct argp ppam_argp = {argp_opts, 0, 0, ppam_doc};
