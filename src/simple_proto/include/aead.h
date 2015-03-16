/* Copyright 2015 Freescale Semiconductor, Inc.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef AEAD_H_
#define AEAD_H_

#include <argp.h>
#include <inttypes.h>

#include <usdpaa/compat.h>

#include <flib/desc/ipsec.h>

#include <crypto/test_utils.h>

#include "common.h"

/* IPSec ESP specific defines */
#define SPI_SIZE	4	/* Security Parameters Index length in bytes */
#define SEQNUM_SIZE	4	/* Sequence number length in bytes.
				   @note: Extended SN is NOT supported */
#define PAD_LEN_SIZE	1	/* Padding length field length in bytes */
#define N_SIZE		1	/* Next header field length in bytes */

/* AEAD specific defines */
#define SG_IN_ENTRIES	4	/* The number of SG entries needed for input */

#define SG_IN_IV		0
#define SG_IN_AONLY		1
#define SG_IN_PAYLOAD		2
#define SG_AONLY_SEQ_NUM_SPI	0
#define SG_AONLY_IV		1


/**
 * IPSEC parameter options specific defines
 */
#define	BMASK_AEAD_CIPHER	0x80000000  /**< Cipher selected for AEAD */
#define	BMASK_AEAD_INTEGRITY	0x40000000  /**< Integrity selected for AEAD */

#define BMASK_AEAD_VALID	(BMASK_AEAD_CIPHER | BMASK_AEAD_INTEGRITY)

/**
 * @def AEAD_TEST_ARRAY_OFFSET
 * @brief The following macro computes the index in the AEAD test vectors array
 * by using the following property of the test array:
 * for each ciphering algorithm, the various parameters that can be given
 * by the user are indexed by their actual values.
 * In short, this macro uses the linear property of the test vectors array.
 */
#define AEAD_TEST_ARRAY_OFFSET(aead_params)			\
	((aead_params)->c_alg * AEAD_AUTH_TYPE_INVALID +	\
	 (aead_params)->i_alg)

enum cipher_type_aead {
	AEAD_CIPHER_TYPE_TDES,
	AEAD_CIPHER_TYPE_INVALID
};

enum auth_type_aead {
	AEAD_AUTH_TYPE_HMAC_MD5_96,
	AEAD_AUTH_TYPE_INVALID
};

struct aead_params {
	enum cipher_type_aead c_alg;
	enum auth_type_aead i_alg;
};

struct protocol_info *register_aead(void);

#endif /* AEAD_H_ */
