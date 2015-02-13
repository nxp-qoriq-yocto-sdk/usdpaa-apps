/* Copyright 2014 Freescale Semiconductor, Inc.
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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MBMS_TEST_VECTOR_H_
#define MBMS_TEST_VECTOR_H_

/**
 * Structure which defines a MBMS test vector.
 */
struct mbms_ref_vector_s {
	union {
		uintptr_t key;			/**< Used when the key contents
						     are supposed to be copied
						     by RTA as immediate in the
						     created descriptor. */
		dma_addr_t dma_addr_key;	/**< Used when a pointer to
						     the key is supposed to be
						     used as-is by RTA in the
						     created descriptor. */
	};
	unsigned char cipher_alg;
	unsigned short cipher_keylen;
	unsigned char auth_alg;
	union {
		uintptr_t auth_key;		/**< Used when the key contents
						     are supposed to be copied
						     by RTA as immediate in the
						     created descriptor. */
		dma_addr_t dma_addr_auth_key;	/**< Used when a pointer to
						     the key is supposed to be
						     used as-is by RTA in the
						     created descriptor. */
	};
	unsigned short auth_keylen;
	uint32_t length;
	uint8_t *plaintext;
	uint8_t *ciphertext;
	/*
	 * NOTE: Keep members above unchanged!
	 */
	unsigned int expected_status;		/**< FD status expected for
						     this test vector. */
	unsigned int expected_outlen;		/**< Output length expected
						     for this test vector. */
	int expected_hdr_crc_fail;		/**< # of expected Header CRC
						     failures. */
	int expected_payload_crc_fail;		/**< # of expected Payload CRC
						     failures. */
};

struct mbms_test_param {
	uint8_t type;
};

uint8_t mbms_prebuffer_data[] = {
	/* 16B = private DPA eth */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 64B = extra headroom */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 64B = IC */
		/* FD = 16B */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* ICAD = 8B */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* CCBASE & KS & HPNIA = 4 + 1 + 3 = 8B */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* PR = 32B */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
	/* 48B = extra buffer space */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t *mbms_type0_test_data[] = {
	(uint8_t[]){
		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x00,
		0x00, 0x03,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x20,
		0x74
	},
	(uint8_t[]){
		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x00,
		0x00, 0x03,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x20,
		0xFE	/* Wrong Header CRC */
	}
};

uint32_t mbms_type0_test_data_in_len[] = {
	68,
	68
};


uint32_t mbms_type0_test_data_out_len[] = {
	68,
	0
};

uint8_t mbms_type0_fd_status[] = {
	0,
	MBMS_CRC_HDR_FAIL
};

int mbms_type0_hdr_crc_fail[] = {
	0,
	/*
	 * Since it's impossible to know beforehand how many buffers, iterations
	 * etc. the user will select at runtime, a placeholder is used here,
	 * which means that the app will calculate the proper number of
	 * failed CRCs
	 */
	-1
};

uint8_t *mbms_type1_test_data_in[] = {
	/* Header CRC = OK, Payload CRC = OK */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x10,				/* PDU Type = 1 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x1D, 0xBA,			/* HDR CRC = 0x1C &
						   Payload CRC = 0x1BA*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	},
	/* Header CRC = OK, Payload CRC = KO */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x10,				/* PDU Type = 1 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x1D, 0xBB,			/* HDR CRC = 0x1C &
						   Payload CRC = 0x1BB*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	},
	/* Header CRC = KO, Payload CRC = OK */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x10,				/* PDU Type = 1 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x2D, 0xBA,			/* HDR CRC = 0x2C &
						   Payload CRC = 0x1BA*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	}
};

uint32_t mbms_type1_test_data_in_len[] = {
	93,
	93,
	93
};

uint8_t mbms_type1_fd_status[] = {
	0,
	MBMS_CRC_PAYLOAD_FAIL,
	MBMS_CRC_HDR_FAIL
};

uint8_t *mbms_type1_test_data_out[] = {
	/* Header CRC = OK, Payload CRC = OK */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x10,				/* PDU Type = 1 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x1D, 0xBA,			/* HDR CRC = 0x1C &
						   Payload CRC = 0x1BA*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	},
	/* Header CRC = OK, Payload CRC = KO */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x10,				/* PDU Type = 1 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x1D, 0xBA			/* HDR CRC = 0x1C &
						   Payload CRC = 0x1BA*/
	},
	/* Header CRC = KO, Payload CRC = OK */
	(uint8_t[]){}
};

uint32_t mbms_type1_test_data_out_len[] = {
	93,
	61,
	0
};

int mbms_type1_hdr_crc_fail[] = {
	0,
	0,
	/*
	 * Since it's impossible to know beforehand how many buffers, iterations
	 * etc. the user will select at runtime, a placeholder is used here,
	 * which means that the app will calculate the proper number of
	 * failed CRCs
	 */
	-1,
};

int mbms_type1_payload_crc_fail[] = {
	0,
	/*
	 * Since it's impossible to know beforehand how many buffers, iterations
	 * etc. the user will select at runtime, a placeholder is used here,
	 * which means that the app will calculate the proper number of
	 * failed CRCs
	 */
	-1,
	0
};

uint8_t *mbms_type3_test_data_in[] = {
	/* Header CRC = OK, Payload CRC = OK */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x30,				/* PDU Type = 3 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x00, 0x00, 0x02,		/* Total # of Packet */
		0x00, 0x00, 0x00, 0x00, 0x30,	/* Total # of Octet */
		0x39, 0xBA,			/* HDR CRC = 0xE &
						   Payload CRC = 0x1BA */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	},
	/* Header CRC = OK, Payload CRC = KO */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x30,				/* PDU Type = 3 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x00, 0x00, 0x02,		/* Total # of Packet */
		0x00, 0x00, 0x00, 0x00, 0x30,	/* Total # of Octet */
		0x39, 0xBB,			/* HDR CRC = 0xE &
						   Payload CRC = 0x1BB */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	},
	/* Header CRC = OK, Payload CRC = OK */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x30,				/* PDU Type = 3 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x00, 0x00, 0x02,		/* Total # of Packet */
		0x00, 0x00, 0x00, 0x00, 0x30,	/* Total # of Octet */
		0x3D, 0xBA,			/* HDR CRC = 0xF &
						   Payload CRC = 0x1BA */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	},
};

uint32_t mbms_type3_test_data_in_len[] = {
	101,
	101,
	101
};

uint8_t mbms_type3_fd_status[] = {
	0,
	MBMS_CRC_PAYLOAD_FAIL,
	MBMS_CRC_HDR_FAIL
};

uint8_t *mbms_type3_test_data_out[] = {
	/* Header CRC = OK, Payload CRC = OK */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x30,				/* PDU Type = 3 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x00, 0x00, 0x02,		/* Total # of Packet */
		0x00, 0x00, 0x00, 0x00, 0x30,	/* Total # of Octet */
		0x39, 0xBA,			/* HDR CRC = 0xE &
						   Payload CRC = 0x1BA */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	},
	/* Header CRC = OK, Payload CRC = KO */
	(uint8_t[]){		/* MAC D, MAC S & ETYPE*/
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x08, 0x00,
		/* IP Header */
		0x45, 0x00, 0x00, 0x36, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0xf3, 0xf2,
		/* IP Source */
		0xc0, 0xa8, 0x0a, 0x01,
		/*IP Dest */
		0xc0, 0xa8, 0x0a, 0x02,
		/* Sport */
		0x08, 0x68,
		/* Dport */
		0x08, 0x68,
		/* Len */
		0x00, 0x22,
		/* Checksum */
		0x00, 0x00,
		/* GTP */
		0x30,
		0xff,
		0x00, 0x1a,
		0x00, 0x00, 0x00, 0x01,
		/* SYNC */
		0x30,				/* PDU Type = 3 */
		0x00, 0x03,			/* TS */
		0x00, 0x01,			/* Pkt number */
		0x00, 0x00, 0x00, 0x01,		/* Elapsed octet counter */
		0x00, 0x00, 0x02,		/* Total # of Packet */
		0x00, 0x00, 0x00, 0x00, 0x30,	/* Total # of Octet */
		0x39, 0xBA,			/* HDR CRC = 0xE &
						   Payload CRC = 0x1BA */
	},
	/* Header CRC = KO */
	(uint8_t[]){}
};

uint32_t mbms_type3_test_data_out_len[] = {
	101,
	69,
	0
};

int mbms_type3_hdr_crc_fail[] = {
	0,
	0,
	/*
	 * Since it's impossible to know beforehand how many buffers, iterations
	 * etc. the user will select at runtime, a placeholder is used here,
	 * which means that the app will calculate the proper number of
	 * failed CRCs
	 */
	-1
};

int mbms_type3_payload_crc_fail[] = {
	0,
	/*
	 * Since it's impossible to know beforehand how many buffers, iterations
	 * etc. the user will select at runtime, a placeholder is used here,
	 * which means that the app will calculate the proper number of
	 * failed CRCs
	 */
	-1,
	0
};

#endif /* MBMS_TEST_VECTOR_H_ */
