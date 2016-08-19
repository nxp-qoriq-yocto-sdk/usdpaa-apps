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

#define PREBUFFER_UDP_OFFSET	(8 * 17 + 6)

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
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 48B = extra buffer space */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t mbms_type0_udp_offset[] = {
	0x22,
	0x22,
	0x3a,
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
		0x14	/* Header CRC = 0x05 */
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
	},
	(uint8_t[]){
		/* MAC Dest */
		0x33, 0x33, 0x83, 0x72, 0xfb, 0x07,
		/* MAC Src */
		0x8c, 0x90, 0xd3, 0x8a, 0x4c, 0x56,
		/* VLAN */
		0x81, 0x00, 0x03, 0xf1, 0x86, 0xdd,
		/* IPv6 header */
		0x68, 0x80, 0x00, 0x00,
		0x00, 0x22, /* Payload length */
		0x11, /* NH = UDP */
		0x3d, /* Hop limit */
		0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x03, /* IPv6 Src */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x79,
		0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPv6 Dst */
		0x00, 0x00, 0x00, 0x00, 0x83, 0x72, 0xfb, 0x07,
		0xcd, 0x8b, /* UDP Src Port */
		0x08, 0x68, /* UDP Dst Port */
		0x00, 0x22, /* UDP Len */
		0x44, 0xf7, /* UDP checksum */
		0x30, 0xff, 0x00, 0x12, 0x00, 0x00, 0x01, 0x61, /* GTP header */
		/* SYNC */
		0x00, /* PDU Type */
		0x00, 0x80, /* Timestamp */
		0x00, 0x0c, /* Packet Number */
		0x00, 0x00, 0x35, 0x40, /* Elapsed Octet Counter */
		0x00, 0x00, 0xa6, /* Total Number of Packets */
		0x00, 0x00, 0x02, 0xdd, 0x50, /* Total Number of Octet */
		0x64 /* Header Checksum */
	}
};

uint32_t mbms_type0_test_data_in_len[] = {
	68,
	68,
	92
};


uint32_t mbms_type0_test_data_out_len[] = {
	68,
	0,
	92
};

uint8_t mbms_type0_fd_status[] = {
	0,
	MBMS_CRC_HDR_FAIL,
	0
};

int mbms_type0_hdr_crc_fail[] = {
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

uint8_t mbms_type1_udp_offset[] = {
	0x22,
	0x22,
	0x22,
	0x3a,
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
		0x00, 0x80,			/* TS */
		0x00, 0x08,			/* Pkt number */
		0x00, 0x00, 0x23, 0x80,		/* Elapsed octet counter */
		0x55, 0x19,			/* HDR CRC = 0x15 &
						   Payload CRC = 0x119*/
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
		0x00, 0x80,			/* TS */
		0x00, 0x08,			/* Pkt number */
		0x00, 0x00, 0x23, 0x80,		/* Elapsed octet counter */
		0x54, 0xFF,			/* HDR CRC = 0x15 &
						   Payload CRC = 0x0FF*/
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
	},
	(uint8_t[]){
		0x33, 0x33, 0x88, 0x7a, 0x37, 0xfb, 0x8c, 0x90, 0xd3, 0x8a,
		0x4c, 0x56, 0x81, 0x00, 0x03, 0xf1, 0x86, 0xdd, 0x68, 0x80,
		0x00, 0x00, 0x03, 0xb9, 0x11, 0x3d, 0xfd, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x79, 0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x88, 0x7a, 0x37, 0xfb, 0xb8, 0x5a,
		0x08, 0x68, 0x03, 0xb9, 0xa3, 0xdd, 0x30, 0xff, 0x03, 0xa9,
		0x00, 0x00, 0x03, 0xb0, 0x10, 0x00, 0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xe7, 0x06, 0x60, 0x00, 0x00, 0x00, 0x03,
		0x76, 0x11, 0x01, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
		0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x38, 0xff,
		0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x95, 0x77, 0x70, 0x00, 0xba, 0xbe, 0x75, 0x33, 0x03,
		0x76, 0x3a, 0xa7, 0x10, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x50, 0x4f, 0x00, 0x00, 0x40, 0x04, 0x00, 0x00, 0x00,
		0x00, 0x03, 0x4a, 0x00, 0x00, 0x04, 0x30, 0x00, 0x00, 0xff,
		0xff, 0xc0, 0x19, 0xe3, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x3c,
		0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,
		0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x65,
		0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x55,
		0x54, 0x46, 0x2d, 0x38, 0x22, 0x20, 0x73, 0x74, 0x61, 0x6e,
		0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x3d, 0x22, 0x6e, 0x6f,
		0x22, 0x20, 0x3f, 0x3e, 0x3c, 0x46, 0x44, 0x54, 0x2d, 0x49,
		0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x20, 0x45, 0x78,
		0x70, 0x69, 0x72, 0x65, 0x73, 0x3d, 0x22, 0x33, 0x36, 0x36,
		0x38, 0x31, 0x34, 0x32, 0x31, 0x30, 0x39, 0x22, 0x20, 0x46,
		0x45, 0x43, 0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x46, 0x45, 0x43,
		0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2d,
		0x49, 0x44, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x46, 0x45, 0x43,
		0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x4d, 0x61, 0x78, 0x2d, 0x4e,
		0x75, 0x6d, 0x62, 0x65, 0x72, 0x2d, 0x6f, 0x66, 0x2d, 0x45,
		0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2d, 0x53, 0x79,
		0x6d, 0x62, 0x6f, 0x6c, 0x73, 0x3d, 0x22, 0x39, 0x34, 0x32,
		0x31, 0x22, 0x20, 0x46, 0x45, 0x43, 0x2d, 0x4f, 0x54, 0x49,
		0x2d, 0x4d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x2d, 0x53,
		0x6f, 0x75, 0x72, 0x63, 0x65, 0x2d, 0x42, 0x6c, 0x6f, 0x63,
		0x6b, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22,
		0x38, 0x31, 0x39, 0x32, 0x22, 0x20, 0x78, 0x6d, 0x6c, 0x6e,
		0x73, 0x3d, 0x22, 0x75, 0x72, 0x6e, 0x3a, 0x49, 0x45, 0x54,
		0x46, 0x3a, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
		0x3a, 0x32, 0x30, 0x30, 0x35, 0x3a, 0x46, 0x4c, 0x55, 0x54,
		0x45, 0x3a, 0x46, 0x44, 0x54, 0x22, 0x3e, 0x3c, 0x46, 0x69,
		0x6c, 0x65, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
		0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22, 0x38,
		0x34, 0x36, 0x33, 0x22, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65,
		0x6e, 0x74, 0x2d, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f,
		0x6e, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
		0x77, 0x77, 0x77, 0x2e, 0x61, 0x6c, 0x63, 0x61, 0x74, 0x65,
		0x6c, 0x2d, 0x6c, 0x75, 0x63, 0x65, 0x6e, 0x74, 0x2e, 0x63,
		0x6f, 0x6d, 0x2f, 0x61, 0x75, 0x64, 0x69, 0x6f, 0x2d, 0x32,
		0x30, 0x38, 0x2e, 0x33, 0x67, 0x70, 0x22, 0x20, 0x43, 0x6f,
		0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4d, 0x44, 0x35, 0x3d,
		0x22, 0x57, 0x2f, 0x67, 0x48, 0x72, 0x53, 0x73, 0x36, 0x72,
		0x6e, 0x66, 0x36, 0x38, 0x44, 0x58, 0x72, 0x59, 0x62, 0x42,
		0x32, 0x36, 0x77, 0x3d, 0x3d, 0x22, 0x20, 0x43, 0x6f, 0x6e,
		0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3d,
		0x22, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
		0x6f, 0x6e, 0x2f, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x2d, 0x73,
		0x74, 0x72, 0x65, 0x61, 0x6d, 0x22, 0x20, 0x46, 0x45, 0x43,
		0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64,
		0x69, 0x6e, 0x67, 0x2d, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c,
		0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22, 0x31,
		0x30, 0x37, 0x32, 0x22, 0x20, 0x46, 0x45, 0x43, 0x2d, 0x4f,
		0x54, 0x49, 0x2d, 0x53, 0x63, 0x68, 0x65, 0x6d, 0x65, 0x2d,
		0x53, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x2d, 0x49,
		0x6e, 0x66, 0x6f, 0x3d, 0x22, 0x41, 0x41, 0x45, 0x42, 0x43,
		0x41, 0x3d, 0x3d, 0x22, 0x20, 0x54, 0x4f, 0x49, 0x3d, 0x22,
		0x32, 0x39, 0x32, 0x32, 0x34, 0x22, 0x20, 0x54, 0x72, 0x61,
		0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x4c, 0x65, 0x6e, 0x67,
		0x74, 0x68, 0x3d, 0x22, 0x38, 0x34, 0x36, 0x33, 0x22, 0x2f,
		0x3e, 0x3c, 0x46, 0x69, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0x6e,
		0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74,
		0x68, 0x3d, 0x22, 0x39, 0x32, 0x32, 0x32, 0x33, 0x22, 0x20,
		0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x6f,
		0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x68, 0x74,
		0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x61,
		0x6c, 0x63, 0x61, 0x74, 0x65, 0x6c, 0x2d, 0x6c, 0x75, 0x63,
		0x65, 0x6e, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x71, 0x73,
		0x75, 0x72, 0x66, 0x5f, 0x37, 0x38, 0x34, 0x5f, 0x6d, 0x61,
		0x69, 0x6e, 0x2d, 0x32, 0x30, 0x38, 0x2e, 0x33, 0x67, 0x70,
		0x22, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,
		0x4d, 0x44, 0x35, 0x3d, 0x22, 0x49, 0x44, 0x49, 0x34, 0x4d,
		0x62, 0x77, 0x2f, 0x37, 0x73, 0x61, 0x37, 0x47, 0x68, 0x4d,
		0x4a, 0x46, 0x32, 0x38, 0x4b, 0x55, 0x67, 0x3d, 0x3d, 0x22,
		0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54,
		0x79, 0x70, 0x65, 0x3d, 0x22, 0x61, 0x70, 0x70, 0x6c, 0x69,
		0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6f, 0x63, 0x74,
		0x65, 0x74, 0x2d, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x22,
		0x20, 0x46, 0x45, 0x43, 0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x45,
		0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2d, 0x53, 0x79,
		0x6d, 0x62, 0x6f, 0x6c, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74,
		0x68, 0x3d, 0x22, 0x31, 0x30, 0x37, 0x32, 0x22, 0x20, 0x46,
		0x45, 0x43, 0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x53, 0x63, 0x68,
		0x65, 0x6d, 0x65, 0x2d, 0x53, 0x70, 0x65, 0x63, 0x69, 0x66,
		0x69, 0x63, 0x2d, 0x49, 0x6e, 0x66, 0x6f, 0x3d, 0x22, 0x41,
		0x41, 0x45, 0x42, 0x43, 0x41, 0x3d, 0x3d, 0x22, 0x20, 0x54,
		0x4f, 0x49, 0x3d, 0x22, 0x32, 0x39, 0x32, 0x32, 0x35, 0x22,
		0x20, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d,
		0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22, 0x39, 0x32,
		0x32, 0x32, 0x33, 0x22, 0x2f, 0x3e, 0x3c, 0x2f, 0x46, 0x44,
		0x54, 0x2d, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65,
		0x3e, 0x86, 0x4b, 0xfd, 0x29,
	}
};

uint32_t mbms_type1_test_data_in_len[] = {
	93,
	93,
	93,
	1011
};

uint8_t mbms_type1_fd_status[] = {
	0,
	MBMS_CRC_PAYLOAD_FAIL,
	MBMS_CRC_HDR_FAIL,
	0,
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
		0x10,				/* PDU Type = 1 */
		0x00, 0x80,			/* TS */
		0x00, 0x08,			/* Pkt number */
		0x00, 0x00, 0x23, 0x80,		/* Elapsed octet counter */
		0x55, 0x19,			/* HDR CRC = 0x15 &
						   Payload CRC = 0x119*/
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
		0x00, 0x80,			/* TS */
		0x00, 0x08,			/* Pkt number */
		0x00, 0x00, 0x23, 0x80,		/* Elapsed octet counter */
		0x55, 0x19,			/* HDR CRC = 0x15 &
						   Payload CRC = 0x119*/
	},
	/* Header CRC = KO, Payload CRC = OK */
	(uint8_t[]){},
	/* Header CRC = OK, Payload CRC = OK */
	(uint8_t[]){
		0x33, 0x33, 0x88, 0x7a, 0x37, 0xfb, 0x8c, 0x90, 0xd3, 0x8a,
		0x4c, 0x56, 0x81, 0x00, 0x03, 0xf1, 0x86, 0xdd, 0x68, 0x80,
		0x00, 0x00, 0x03, 0xb9, 0x11, 0x3d, 0xfd, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x79, 0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x88, 0x7a, 0x37, 0xfb, 0xb8, 0x5a,
		0x08, 0x68, 0x03, 0xb9, 0xa3, 0xdd, 0x30, 0xff, 0x03, 0xa9,
		0x00, 0x00, 0x03, 0xb0, 0x10, 0x00, 0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xe7, 0x06, 0x60, 0x00, 0x00, 0x00, 0x03,
		0x76, 0x11, 0x01, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
		0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x38, 0xff,
		0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x95, 0x77, 0x70, 0x00, 0xba, 0xbe, 0x75, 0x33, 0x03,
		0x76, 0x3a, 0xa7, 0x10, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x50, 0x4f, 0x00, 0x00, 0x40, 0x04, 0x00, 0x00, 0x00,
		0x00, 0x03, 0x4a, 0x00, 0x00, 0x04, 0x30, 0x00, 0x00, 0xff,
		0xff, 0xc0, 0x19, 0xe3, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x3c,
		0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,
		0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x65,
		0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x55,
		0x54, 0x46, 0x2d, 0x38, 0x22, 0x20, 0x73, 0x74, 0x61, 0x6e,
		0x64, 0x61, 0x6c, 0x6f, 0x6e, 0x65, 0x3d, 0x22, 0x6e, 0x6f,
		0x22, 0x20, 0x3f, 0x3e, 0x3c, 0x46, 0x44, 0x54, 0x2d, 0x49,
		0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x20, 0x45, 0x78,
		0x70, 0x69, 0x72, 0x65, 0x73, 0x3d, 0x22, 0x33, 0x36, 0x36,
		0x38, 0x31, 0x34, 0x32, 0x31, 0x30, 0x39, 0x22, 0x20, 0x46,
		0x45, 0x43, 0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x46, 0x45, 0x43,
		0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2d,
		0x49, 0x44, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x46, 0x45, 0x43,
		0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x4d, 0x61, 0x78, 0x2d, 0x4e,
		0x75, 0x6d, 0x62, 0x65, 0x72, 0x2d, 0x6f, 0x66, 0x2d, 0x45,
		0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2d, 0x53, 0x79,
		0x6d, 0x62, 0x6f, 0x6c, 0x73, 0x3d, 0x22, 0x39, 0x34, 0x32,
		0x31, 0x22, 0x20, 0x46, 0x45, 0x43, 0x2d, 0x4f, 0x54, 0x49,
		0x2d, 0x4d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x2d, 0x53,
		0x6f, 0x75, 0x72, 0x63, 0x65, 0x2d, 0x42, 0x6c, 0x6f, 0x63,
		0x6b, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22,
		0x38, 0x31, 0x39, 0x32, 0x22, 0x20, 0x78, 0x6d, 0x6c, 0x6e,
		0x73, 0x3d, 0x22, 0x75, 0x72, 0x6e, 0x3a, 0x49, 0x45, 0x54,
		0x46, 0x3a, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
		0x3a, 0x32, 0x30, 0x30, 0x35, 0x3a, 0x46, 0x4c, 0x55, 0x54,
		0x45, 0x3a, 0x46, 0x44, 0x54, 0x22, 0x3e, 0x3c, 0x46, 0x69,
		0x6c, 0x65, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
		0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22, 0x38,
		0x34, 0x36, 0x33, 0x22, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65,
		0x6e, 0x74, 0x2d, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f,
		0x6e, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
		0x77, 0x77, 0x77, 0x2e, 0x61, 0x6c, 0x63, 0x61, 0x74, 0x65,
		0x6c, 0x2d, 0x6c, 0x75, 0x63, 0x65, 0x6e, 0x74, 0x2e, 0x63,
		0x6f, 0x6d, 0x2f, 0x61, 0x75, 0x64, 0x69, 0x6f, 0x2d, 0x32,
		0x30, 0x38, 0x2e, 0x33, 0x67, 0x70, 0x22, 0x20, 0x43, 0x6f,
		0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4d, 0x44, 0x35, 0x3d,
		0x22, 0x57, 0x2f, 0x67, 0x48, 0x72, 0x53, 0x73, 0x36, 0x72,
		0x6e, 0x66, 0x36, 0x38, 0x44, 0x58, 0x72, 0x59, 0x62, 0x42,
		0x32, 0x36, 0x77, 0x3d, 0x3d, 0x22, 0x20, 0x43, 0x6f, 0x6e,
		0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3d,
		0x22, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69,
		0x6f, 0x6e, 0x2f, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x2d, 0x73,
		0x74, 0x72, 0x65, 0x61, 0x6d, 0x22, 0x20, 0x46, 0x45, 0x43,
		0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64,
		0x69, 0x6e, 0x67, 0x2d, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c,
		0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22, 0x31,
		0x30, 0x37, 0x32, 0x22, 0x20, 0x46, 0x45, 0x43, 0x2d, 0x4f,
		0x54, 0x49, 0x2d, 0x53, 0x63, 0x68, 0x65, 0x6d, 0x65, 0x2d,
		0x53, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x2d, 0x49,
		0x6e, 0x66, 0x6f, 0x3d, 0x22, 0x41, 0x41, 0x45, 0x42, 0x43,
		0x41, 0x3d, 0x3d, 0x22, 0x20, 0x54, 0x4f, 0x49, 0x3d, 0x22,
		0x32, 0x39, 0x32, 0x32, 0x34, 0x22, 0x20, 0x54, 0x72, 0x61,
		0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x4c, 0x65, 0x6e, 0x67,
		0x74, 0x68, 0x3d, 0x22, 0x38, 0x34, 0x36, 0x33, 0x22, 0x2f,
		0x3e, 0x3c, 0x46, 0x69, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0x6e,
		0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74,
		0x68, 0x3d, 0x22, 0x39, 0x32, 0x32, 0x32, 0x33, 0x22, 0x20,
		0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x6f,
		0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x68, 0x74,
		0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x61,
		0x6c, 0x63, 0x61, 0x74, 0x65, 0x6c, 0x2d, 0x6c, 0x75, 0x63,
		0x65, 0x6e, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x71, 0x73,
		0x75, 0x72, 0x66, 0x5f, 0x37, 0x38, 0x34, 0x5f, 0x6d, 0x61,
		0x69, 0x6e, 0x2d, 0x32, 0x30, 0x38, 0x2e, 0x33, 0x67, 0x70,
		0x22, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,
		0x4d, 0x44, 0x35, 0x3d, 0x22, 0x49, 0x44, 0x49, 0x34, 0x4d,
		0x62, 0x77, 0x2f, 0x37, 0x73, 0x61, 0x37, 0x47, 0x68, 0x4d,
		0x4a, 0x46, 0x32, 0x38, 0x4b, 0x55, 0x67, 0x3d, 0x3d, 0x22,
		0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54,
		0x79, 0x70, 0x65, 0x3d, 0x22, 0x61, 0x70, 0x70, 0x6c, 0x69,
		0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6f, 0x63, 0x74,
		0x65, 0x74, 0x2d, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x22,
		0x20, 0x46, 0x45, 0x43, 0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x45,
		0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x2d, 0x53, 0x79,
		0x6d, 0x62, 0x6f, 0x6c, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74,
		0x68, 0x3d, 0x22, 0x31, 0x30, 0x37, 0x32, 0x22, 0x20, 0x46,
		0x45, 0x43, 0x2d, 0x4f, 0x54, 0x49, 0x2d, 0x53, 0x63, 0x68,
		0x65, 0x6d, 0x65, 0x2d, 0x53, 0x70, 0x65, 0x63, 0x69, 0x66,
		0x69, 0x63, 0x2d, 0x49, 0x6e, 0x66, 0x6f, 0x3d, 0x22, 0x41,
		0x41, 0x45, 0x42, 0x43, 0x41, 0x3d, 0x3d, 0x22, 0x20, 0x54,
		0x4f, 0x49, 0x3d, 0x22, 0x32, 0x39, 0x32, 0x32, 0x35, 0x22,
		0x20, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d,
		0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x22, 0x39, 0x32,
		0x32, 0x32, 0x33, 0x22, 0x2f, 0x3e, 0x3c, 0x2f, 0x46, 0x44,
		0x54, 0x2d, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65,
		0x3e
	}
};

uint32_t mbms_type1_test_data_out_len[] = {
	93,
	61,
	0,
	1011
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
	0,
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
	0,
	0
};

uint8_t mbms_type3_udp_offset[] = {
	0x22,
	0x22,
	0x22,
	0x3a,
	0x3a
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
		0x59, 0x19,			/* HDR CRC = 0x16 &
						   Payload CRC = 0x119 */
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
		0x59, 0xFF,			/* HDR CRC = 0x16 &
						   Payload CRC = 0x1FF */
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
	(uint8_t[]) {
		0x33, 0x33, 0x96, 0x57, 0xa3, 0x27, 0x8c, 0x90, 0xd3, 0x8a,
		0x4c, 0x56, 0x81, 0x00, 0x03, 0xf1, 0x86, 0xdd, 0x68, 0x80,
		0x00, 0x00, 0x00, 0x37, 0x11, 0x3d, 0xfd, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x79, 0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x96, 0x57, 0xa3, 0x27, 0xb4, 0xf4,
		0x08, 0x68, 0x00, 0x37, 0x88, 0x3a, 0x30, 0xff, 0x00, 0x27,
		0x00, 0x00, 0x01, 0xc9, 0x30, 0x00, 0x80, 0x00, 0x0d, 0x00,
		0x00, 0x39, 0xb0, 0x00, 0x00, 0xca, 0x00, 0x00, 0x03, 0x7e,
		0xc0, 0xc7, 0xd4, 0x47, 0x04, 0x70, 0x47, 0x04, 0x70, 0x47,
		0x04, 0x70, 0x47, 0x04, 0x70, 0x47, 0x04, 0x70, 0x47, 0x04,
		0x70, 0x47, 0x00,
	},
	(uint8_t[]) {
		0x33, 0x33, 0xcf, 0x38, 0x9c, 0x30, 0x8c, 0x90, 0xd3, 0x8a,
		0x4c, 0x56, 0x81, 0x00, 0x03, 0xf1, 0x86, 0xdd, 0x68, 0x80,
		0x00, 0x00, 0x00, 0x35, 0x11, 0x3d, 0xfd, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x79, 0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xcf, 0x38, 0x9c, 0x30, 0xd9, 0x1a,
		0x08, 0x68, 0x00, 0x35, 0xb6, 0xbd, 0x30, 0xff, 0x00, 0x25,
		0x00, 0x00, 0x03, 0x03, 0x30, 0x00, 0x80, 0x00, 0x0c, 0x00,
		0x00, 0x35, 0x40, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x02, 0x6e,
		0x68, 0x99, 0x19, 0x47, 0x04, 0x70, 0x47, 0x04, 0x70, 0x47,
		0x04, 0x70, 0x47, 0x04, 0x70, 0x47, 0x04, 0x70, 0x47, 0x04,
		0x70, 0xcb, 0xfc, 0xfb, 0x0a
	}
};

uint32_t mbms_type3_test_data_in_len[] = {
	101,
	101,
	101,
	113,
	111
};

uint8_t mbms_type3_fd_status[] = {
	0,
	MBMS_CRC_PAYLOAD_FAIL,
	MBMS_CRC_HDR_FAIL,
	0
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
		0x59, 0x19,			/* HDR CRC = 0x16 &
						   Payload CRC = 0x119 */
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
		0x59, 0x19,			/* HDR CRC = 0x16 &
						   Payload CRC = 0x119 */
	},
	/* Header CRC = KO */
	(uint8_t[]){},
	(uint8_t[]) {
		0x33, 0x33, 0x96, 0x57, 0xa3, 0x27, 0x8c, 0x90, 0xd3, 0x8a,
		0x4c, 0x56, 0x81, 0x00, 0x03, 0xf1, 0x86, 0xdd, 0x68, 0x80,
		0x00, 0x00, 0x00, 0x37, 0x11, 0x3d, 0xfd, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x79, 0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x96, 0x57, 0xa3, 0x27, 0xb4, 0xf4,
		0x08, 0x68, 0x00, 0x37, 0x88, 0x3a, 0x30, 0xff, 0x00, 0x27,
		0x00, 0x00, 0x01, 0xc9, 0x30, 0x00, 0x80, 0x00, 0x0d, 0x00,
		0x00, 0x39, 0xb0, 0x00, 0x00, 0xca, 0x00, 0x00, 0x03, 0x7e,
		0xc0, 0xc7, 0xd4, 0x47, 0x04, 0x70, 0x47, 0x04, 0x70, 0x47,
		0x04, 0x70, 0x47, 0x04, 0x70, 0x47, 0x04, 0x70, 0x47, 0x04,
		0x70, 0x47, 0x00,
	},
	(uint8_t[]) {
		0x33, 0x33, 0xcf, 0x38, 0x9c, 0x30, 0x8c, 0x90, 0xd3, 0x8a,
		0x4c, 0x56, 0x81, 0x00, 0x03, 0xf1, 0x86, 0xdd, 0x68, 0x80,
		0x00, 0x00, 0x00, 0x35, 0x11, 0x3d, 0xfd, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x79, 0xff, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xcf, 0x38, 0x9c, 0x30, 0xd9, 0x1a,
		0x08, 0x68, 0x00, 0x35, 0xb6, 0xbd, 0x30, 0xff, 0x00, 0x25,
		0x00, 0x00, 0x03, 0x03, 0x30, 0x00, 0x80, 0x00, 0x0c, 0x00,
		0x00, 0x35, 0x40, 0x00, 0x00, 0x8d, 0x00, 0x00, 0x02, 0x6e,
		0x68, 0x99, 0x19, 0x47, 0x04, 0x70, 0x47, 0x04, 0x70, 0x47,
		0x04, 0x70, 0x47, 0x04, 0x70, 0x47, 0x04, 0x70, 0x47, 0x04,
		0x70, 0xcb, 0xfc, 0xfb, 0x0a
	}
};

uint32_t mbms_type3_test_data_out_len[] = {
	101,
	69,
	0,
	113,
	111
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
	-1,
	0,
	0,
	0,
	0
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
	0,
	0,
	0
};

#endif /* MBMS_TEST_VECTOR_H_ */
