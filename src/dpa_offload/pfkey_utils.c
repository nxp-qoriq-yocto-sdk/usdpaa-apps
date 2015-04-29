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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ipsec.h>
#include <linux/pfkeyv2.h>

#include <compat.h>
#include <fsl_fman.h>
#include <fsl_dpa_ipsec.h>
#include <fsl_dpa_ipsec_algs.h>

#include "pfkey_utils.h"

#define CALLOC(size, cast) (cast)calloc(1, (size))
#define PFKEY_UNUNIT64(a)	((a) << 3)
#define PFKEY_UNIT64(a)		((a) >> 3)

#define PFKEY_ALIGN8(a) (1 + (((a) - 1) | (8 - 1)))
#define PFKEY_EXTLEN(msg) \
	PFKEY_UNUNIT64(((struct sadb_ext *)(msg))->sadb_ext_len)
#define PFKEY_ADDR_PREFIX(ext) \
	(((struct sadb_address *)(ext))->sadb_address_prefixlen)
#define PFKEY_ADDR_PROTO(ext) \
	(((struct sadb_address *)(ext))->sadb_address_proto)
#define PFKEY_ADDR_SADDR(ext) \
	((struct sockaddr *)((caddr_t)(ext) + sizeof(struct sadb_address)))

static u32 xfrm_msg_seq_num = 0;

static inline int get_auth_alg_by_id(int aalg)
{
	if (aalg == SADB_AALG_MD5HMAC)
		return NF_IPSEC_AUTH_ALG_MD5HMAC;
	if (aalg == SADB_AALG_SHA1HMAC)
		return NF_IPSEC_AUTH_ALG_SHA1HMAC;
	if (aalg == SADB_X_AALG_AES_XCBC_MAC)
		return NF_IPSEC_AUTH_ALG_AESXCBC;
	if (aalg == SADB_X_AALG_SHA2_256HMAC)
		return NF_IPSEC_AUTH_ALG_SHA2_256_HMAC;
	if (aalg == SADB_X_AALG_SHA2_384HMAC)
		return NF_IPSEC_AUTH_ALG_SHA2_384_HMAC;
	if (aalg == SADB_X_AALG_SHA2_512HMAC)
		return NF_IPSEC_AUTH_ALG_SHA2_512_HMAC;
	return -1;
}

static inline int get_enc_alg_by_id(int ealg)
{
	if (ealg == SADB_EALG_3DESCBC)
		return NF_IPSEC_ENC_ALG_3DES_CBC;
	if (ealg == SADB_EALG_NULL)
		return NF_IPSEC_ENC_ALG_NULL;
	if (ealg == SADB_X_EALG_AESCBC)
		return NF_IPSEC_ENC_ALG_AES_CBC;
	if (ealg == SADB_X_EALG_AESCTR)
		return NF_IPSEC_ENC_ALG_AES_CTR;
	return -1;
}

int get_auth_alg_by_name(const char *auth_alg_name)
{
	if (!strcmp(auth_alg_name, "hmac(sha1)"))
		return NF_IPSEC_AUTH_ALG_SHA1HMAC;
	if (!strcmp(auth_alg_name, "hmac(md5)"))
		return NF_IPSEC_AUTH_ALG_MD5HMAC;
	if (!strcmp(auth_alg_name, "hmac(sha256)"))
		return NF_IPSEC_AUTH_ALG_SHA2_256_HMAC;
	if (!strcmp(auth_alg_name, "hmac(sha384)"))
		return NF_IPSEC_AUTH_ALG_SHA2_384_HMAC;
	if (!strcmp(auth_alg_name, "hmac(sha512)"))
		return NF_IPSEC_AUTH_ALG_SHA2_512_HMAC;
	if (!strcmp(auth_alg_name, "xcbc(aes)"))
		return NF_IPSEC_AUTH_ALG_AESXCBC;
	/* TODO: treat NULL scenario*/
	return -1;
}

int get_enc_alg_by_name(const char *cipher_alg_name)
{
	if (!strcmp(cipher_alg_name, "ecb(cipher_null)"))
		return NF_IPSEC_ENC_ALG_NULL;
	if (!strcmp(cipher_alg_name, "cbc(des3_ede)"))
		return NF_IPSEC_ENC_ALG_3DES_CBC;
	if (!strcmp(cipher_alg_name, "cbc(aes)"))
		return NF_IPSEC_ENC_ALG_AES_CBC;
	if (!strcmp(cipher_alg_name, "rfc3686(ctr(aes))"))
		return NF_IPSEC_ENC_ALG_AES_CTR;
	/* TODO: treat DES_CBC scenario*/
	return -1;
}

static inline void get_auth_info(struct sadb_key *m_auth,
				 struct nf_ipsec_sa *sa_params)
{
	sa_params->crypto_params.auth_key_len_bits = m_auth->sadb_key_bits;
	sa_params->crypto_params.auth_key =(uint8_t *)
				    ((caddr_t)(void *)m_auth + sizeof(*m_auth));
}

static inline void get_crypt_info(struct sadb_key *m_enc,
				  struct nf_ipsec_sa *sa_params)
{
	sa_params->crypto_params.cipher_key_len_bits = m_enc->sadb_key_bits;
	sa_params->crypto_params.cipher_key = (uint8_t *)(
				       (caddr_t)(void *)m_enc + sizeof(*m_enc));
}

void kdebug_sadb(struct sadb_msg *base)
{
	struct sadb_ext *ext;
	int tlen, extlen;

	if (base == NULL) {
		fprintf(stderr, "kdebug_sadb: NULL pointer was passed.\n");
		return;
	}

	printf("sadb_msg{ version=%u type=%u errno=%u satype=%u\n",
	    base->sadb_msg_version, base->sadb_msg_type,
	    base->sadb_msg_errno, base->sadb_msg_satype);
	printf("  len=%u reserved=%u seq=%u pid=%u\n",
	    base->sadb_msg_len, base->sadb_msg_reserved,
	    base->sadb_msg_seq, base->sadb_msg_pid);

	tlen = PFKEY_UNUNIT64(base->sadb_msg_len) - sizeof(struct sadb_msg);
	ext = (void *)((caddr_t)(void *)base + sizeof(struct sadb_msg));

	while (tlen > 0) {
		printf("sadb_ext{ len=%u type=%u }\n",
		    ext->sadb_ext_len, ext->sadb_ext_type);

		if (ext->sadb_ext_len == 0) {
			printf("kdebug_sadb: invalid ext_len=0 was passed.\n");
			return;
		}
		if (ext->sadb_ext_len > tlen) {
			printf("kdebug_sadb: ext_len exceeds end of buffer.\n");
			return;
		}
		extlen = PFKEY_UNUNIT64(ext->sadb_ext_len);
		tlen -= extlen;
		ext = (void *)((caddr_t)(void *)ext + extlen);
	}
}


int pfkey_open(void)
{
	int so;
	so = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (so < 0)
		return -1;
	return so;
}

void pfkey_close(int so)
{
	close(so);
	return;
}

int pfkey_send(int so, struct sadb_msg *msg, int len)
{
	len = send(so, (void *)msg, (socklen_t)len, 0);
	if (len < 0) {
		fprintf(stderr, "%s ret -1\n", strerror(errno));
		return -1;
	}
	return len;
}

static inline u_int8_t sysdep_sa_len(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	}
	return sizeof(struct sockaddr_in);
}

static inline void sa_getaddr(const struct sockaddr *sa,
			      xfrm_address_t *xaddr)
{
	switch (sa->sa_family) {
	case AF_INET:
		xaddr->a4 = ((struct sockaddr_in *)sa)->sin_addr.s_addr;
		return;
	case AF_INET6:
		memcpy(&xaddr->a6,
		       &((struct sockaddr_in6 *)sa)->sin6_addr,
		       sizeof(struct in6_addr));
		return;
	}
}


static caddr_t pfkey_setsadbmsg(caddr_t buf, caddr_t lim, u_int type,
				u_int tlen, u_int satype, u_int32_t seq,
				pid_t pid)
{
	struct sadb_msg *p;
	u_int len;

	p = (void *)buf;
	len = sizeof(struct sadb_msg);

	if (buf + len > lim)
		return NULL;

	memset(p, 0, len);
	p->sadb_msg_version = PF_KEY_V2;
	p->sadb_msg_type = type;
	p->sadb_msg_errno = 0;
	p->sadb_msg_satype = satype;
	p->sadb_msg_len = PFKEY_UNIT64(tlen);
	p->sadb_msg_reserved = 0;
	p->sadb_msg_seq = seq;
	p->sadb_msg_pid = (u_int32_t)pid;

	return buf + len;
}

/* sending SADB_X_SPDGET */
static int pfkey_send_spdget(int so, u_int32_t request_seq_num, u_int32_t spid)
{
	struct sadb_msg *newmsg;
	struct sadb_x_policy xpl;
	int len;
	caddr_t p;
	caddr_t ep;

	/* create new sadb_msg to reply. */
	len = sizeof(struct sadb_msg) + sizeof(xpl);
	newmsg = CALLOC((size_t)len, struct sadb_msg *);
	if (newmsg == NULL)
		return -1;
	ep = ((caddr_t)(void *)newmsg) + len;

	p = pfkey_setsadbmsg((void *)newmsg, ep, SADB_X_SPDGET, (u_int)len,
	    SADB_SATYPE_UNSPEC, request_seq_num, getpid());
	if (!p) {
		free(newmsg);
		return -1;
	}

	if (p + sizeof(xpl) != ep) {
		free(newmsg);
		return -1;
	}
	memset(&xpl, 0, sizeof(xpl));
	xpl.sadb_x_policy_len = PFKEY_UNIT64(sizeof(xpl));
	xpl.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xpl.sadb_x_policy_id = spid;
	memcpy(p, &xpl, sizeof(xpl));

	/* send message */
	len = pfkey_send(so, newmsg, len);
	free(newmsg);

	if (len < 0)
		return -1;

	return len;
}

int pfkey_recv_sadbmsg(int so, u_int msg_type, u_int32_t seq_num,
						struct sadb_msg **newmsg)
{
	struct sadb_msg buf;
	struct sadb_msg *tmp = NULL;
	int len, reallen;

	do {
		/* Get next SADB message header: */
		while ((len = recv(so, (void *)&buf, sizeof(buf),
							MSG_PEEK)) < 0) {
			if (errno == EINTR)
				continue;
			return len;
		}

		if (len < (int)sizeof(buf)) {
			/* Corrupted message. Just read it and discard it. */
			recv(so, (void *)&buf, sizeof(buf), 0);
			return -EINVAL;
		}

		/* read real message */
		reallen = PFKEY_UNUNIT64(buf.sadb_msg_len);
		tmp = (struct sadb_msg *)realloc(*newmsg, reallen);
		if (!tmp)
			return -ENOMEM;
		*newmsg = tmp;

		while ((len = recv(so, (void *)tmp, (socklen_t)reallen,
								0)) < 0) {
			if (errno == EINTR)
				continue;
			return len;
		}

		/* Expecting to read a full message: */
		if (len != reallen)
			return -EINVAL;

		/* don't trust what the kernel says, validate! */
		if (PFKEY_UNUNIT64(tmp->sadb_msg_len) != len)
			return -EINVAL;
	} while ((tmp->sadb_msg_type != msg_type) ||
				(tmp->sadb_msg_seq != seq_num) ||
				(tmp->sadb_msg_pid != (u_int32_t)getpid()));

	return 0;
}


int
pfkey_align(struct sadb_msg *msg, caddr_t *mhp)
{
	struct sadb_ext *ext;
	int i;
	caddr_t p;
	caddr_t ep;

	/* validity check */
	if (msg == NULL || mhp == NULL)
		return -1;

	/* initialize */
	for (i = 0; i < SADB_EXT_MAX + 1; i++)
		mhp[i] = NULL;

	mhp[0] = (void *)msg;

	/* initialize */
	p = (void *) msg;
	ep = p + PFKEY_UNUNIT64(msg->sadb_msg_len);

	/* skip base header */
	p += sizeof(struct sadb_msg);

	while (p < ep) {
		ext = (void *)p;
		if (ep < p + sizeof(*ext) ||
				PFKEY_EXTLEN(ext) < (int)sizeof(*ext) ||
				ep < p + PFKEY_EXTLEN(ext)) {
			/* invalid format */
			break;
		}

		/* duplicate check */
		/* XXX Are there duplication either KEY_AUTH or KEY_ENCRYPT ?*/
		if (mhp[ext->sadb_ext_type] != NULL)
			return -1;

		/* set pointer */
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_KEY_AUTH:
			/* XXX should to be check weak keys. */
		case SADB_EXT_KEY_ENCRYPT:
			/* XXX should to be check weak keys. */
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
		case SADB_EXT_SENSITIVITY:
		case SADB_EXT_PROPOSAL:
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
		case SADB_EXT_SPIRANGE:
		case SADB_X_EXT_POLICY:
		case SADB_X_EXT_SA2:
#ifdef SADB_X_EXT_NAT_T_TYPE
		case SADB_X_EXT_NAT_T_TYPE:
		case SADB_X_EXT_NAT_T_SPORT:
		case SADB_X_EXT_NAT_T_DPORT:
		case SADB_X_EXT_NAT_T_OA:
#endif
#ifdef SADB_X_EXT_TAG
		case SADB_X_EXT_TAG:
#endif
#ifdef SADB_X_EXT_PACKET
		case SADB_X_EXT_PACKET:
#endif
#ifdef SADB_X_EXT_KMADDRESS
		case SADB_X_EXT_KMADDRESS:
#endif
#ifdef SADB_X_EXT_SEC_CTX
		case SADB_X_EXT_SEC_CTX:
#endif
			mhp[ext->sadb_ext_type] = (void *)ext;
			break;
		default:
			return -1;
		}

		p += PFKEY_EXTLEN(ext);
	}

	if (p != ep)
		return -1;

	return 0;
}

static int
ipsec_dump_ipsecrequest(char *buf __maybe_unused, size_t len __maybe_unused,
			struct sadb_x_ipsecrequest *xisr,
			int bound,
			xfrm_address_t *saddr, xfrm_address_t *daddr,
			int *sa_af)
{
	if (xisr->sadb_x_ipsecrequest_len > bound)
		return -1;

	switch (xisr->sadb_x_ipsecrequest_proto) {
	case IPPROTO_ESP:
	case IPPROTO_AH:
	case IPPROTO_COMP:
		break;
	default:
		return -1;
	}

	switch (xisr->sadb_x_ipsecrequest_mode) {
	case IPSEC_MODE_ANY:
	case IPSEC_MODE_TRANSPORT:
	case IPSEC_MODE_TUNNEL:
		break;
	default:
		return -1;
	}

	switch (xisr->sadb_x_ipsecrequest_level) {
	case IPSEC_LEVEL_DEFAULT:
	case IPSEC_LEVEL_USE:
	case IPSEC_LEVEL_REQUIRE:
	case IPSEC_LEVEL_UNIQUE:
		break;
	default:
		return -1;
	}

	if (xisr->sadb_x_ipsecrequest_len > sizeof(*xisr)) {
		struct sockaddr *sa1, *sa2;
		caddr_t p;
		const int niflags = NI_NUMERICHOST | NI_NUMERICSERV;
		char host1[NI_MAXHOST], host2[NI_MAXHOST];
		char serv1[NI_MAXSERV], serv2[NI_MAXHOST];

		p = (void *)(xisr + 1);
		sa1 = (void *)p;
		sa2 = (void *)(p + sysdep_sa_len(sa1));
		if (sizeof(*xisr) + sysdep_sa_len(sa1) + sysdep_sa_len(sa2) !=
		    xisr->sadb_x_ipsecrequest_len) {
			return -1;
		}
		if (getnameinfo(sa1, (socklen_t)sysdep_sa_len(sa1),
			host1, sizeof(host1),
			serv1, sizeof(serv1), niflags) != 0)
			return -1;
		if (getnameinfo(sa2, (socklen_t)sysdep_sa_len(sa2),
			host2, sizeof(host2),
			serv2, sizeof(serv2), niflags) != 0)
			return -1;
		sa_getaddr(sa1, saddr);
		sa_getaddr(sa2, daddr);
		*sa_af = sa1->sa_family;
	}

	return 0;
}


static int
ipsec_dump_policy(void *policy,
		xfrm_address_t *saddr, xfrm_address_t *daddr,
		int *sa_af)
{
	struct sadb_x_policy *xpl = policy;
	struct sadb_x_ipsecrequest *xisr;
	size_t off;
	char isrbuf[1024];

	/* count length of buffer for use */
	off = sizeof(*xpl);
	while ((int)off < PFKEY_EXTLEN(xpl)) {
		xisr = (void *)((caddr_t)(void *)xpl + off);
		off += xisr->sadb_x_ipsecrequest_len;
	}

	/* validity check */
	if ((int)off != PFKEY_EXTLEN(xpl))
		return -1;
	off = sizeof(*xpl);
	while ((int)off < PFKEY_EXTLEN(xpl)) {
		xisr = (void *)((caddr_t)(void *)xpl + off);

		if (ipsec_dump_ipsecrequest(isrbuf, sizeof(isrbuf), xisr,
		    PFKEY_EXTLEN(xpl) - off, saddr, daddr, sa_af) < 0) {
			return -1;
		}
		off += xisr->sadb_x_ipsecrequest_len;
	}
	return 0;
}

static int
pfkey_spdump(struct sadb_msg *m,
		xfrm_address_t *saddr, xfrm_address_t *daddr,
		int *sa_af)
{
	caddr_t mhp[SADB_EXT_MAX + 1];
	struct sadb_x_policy *m_xpl;

	if (pfkey_align(m, mhp))
		return -1;

	m_xpl = (void *)mhp[SADB_X_EXT_POLICY];
	/* policy */
	if (m_xpl == NULL)
		return -1;

	return ipsec_dump_policy(m_xpl, saddr, daddr, sa_af);
}

int
pfkey_sadump(struct sadb_msg *m,
		struct nf_ipsec_sa *sa_params,
		struct xfrm_encap_tmpl *encap)
{
	caddr_t mhp[SADB_EXT_MAX + 1];
	struct sadb_sa *m_sa;
	struct sadb_key *m_auth, *m_enc;
	struct sadb_x_nat_t_port *natt_sport, *natt_dport;

	if (pfkey_align(m, mhp))
		return -1;

	m_sa = (void *)mhp[SADB_EXT_SA];
	m_auth = (void *)mhp[SADB_EXT_KEY_AUTH];
	m_enc = (void *)mhp[SADB_EXT_KEY_ENCRYPT];
	natt_sport = (void *)mhp[SADB_X_EXT_NAT_T_SPORT];
	natt_dport = (void *)mhp[SADB_X_EXT_NAT_T_DPORT];

	if (!m_sa)
		return -1;
	if (!m_enc)
		return -1;
	if (!m_auth)
		return -1;

	get_crypt_info(m_enc, sa_params);
	get_auth_info(m_auth, sa_params);
	sa_params->crypto_params.auth_algo =
			get_auth_alg_by_id(m_sa->sadb_sa_auth);
	sa_params->crypto_params.cipher_algo =
			get_enc_alg_by_id(m_sa->sadb_sa_encrypt);
	if (natt_sport && natt_dport) {
		encap->encap_sport =
			ntohs(natt_sport->sadb_x_nat_t_port_port);
		encap->encap_dport =
			ntohs(natt_dport->sadb_x_nat_t_port_port);
	}

	return 0;
}

int
do_spdget(int spid, xfrm_address_t *saddr, xfrm_address_t *daddr, int *sa_af)
{
	int ret;
	struct sadb_msg *m = NULL;

	int so = pfkey_open();
	if (so < 0) {
		error(0, EIO, "Failed to open PF_KEY socket");
		return -EIO;
	}
	ret = pfkey_send_spdget(so, xfrm_msg_seq_num, spid);
	if (ret < 0) {
		error(0, -ret, "Failed to send SADB_X_SPDGET");
		return ret;
	}
	ret = pfkey_recv_sadbmsg(so, SADB_X_SPDGET, xfrm_msg_seq_num++, &m);
	if (ret < 0) {
		error(0, -ret, "Failed to receive from PF_KEY socket");
		free(m);
		pfkey_close(so);
		return ret;
	}
	pfkey_close(so);
	ret = pfkey_spdump(m, saddr, daddr, sa_af);
	free(m);
	return ret;
}
