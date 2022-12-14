/* Copyright 2013 Freescale Semiconductor, Inc.
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
#ifndef MACSEC_TEST_VECTOR_H_
#define MACSEC_TEST_VECTOR_H_

#include <inttypes.h>
#include <compat.h>

#define MACSEC_ICV_SIZE     16
#define MACSEC_SECTAG_SIZE  16
#define MACSEC_IV_SCI_SIZE  8
#define MACSEC_IV_SIZE      12
#define MACSEC_SCI_ENABLE   1
#define MACSEC_ETYPE_SIZE   2
#define MACSEC_TCIAN_SIZE   1
#define MACSEC_IV_PN_SIZE   4
#define MACSEC_KEY_SIZE     16
#define MACSEC_GMAC_TEST_ID 4

#define MACSEC_MAX_TEST_PLAIN_PACKET_SIZE	79
#define MACSEC_MAX_TEST_ENCRYPT_PACKET_SIZE	\
					(MACSEC_MAX_TEST_PLAIN_PACKET_SIZE +\
					 MACSEC_ICV_SIZE +\
					 MACSEC_SECTAG_SIZE)

/**
 * Structure which defines a MACsec test vector.
 */
struct macsec_ref_vector_s {
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
	uint64_t sci;
	uint16_t ethertype;
	uint8_t tci_an;
	uint32_t pn;
};

static uint8_t macsec_reference_key[][MACSEC_KEY_SIZE] = {
	/* gcm - encryption and authentication */
	/* 54 bytes */
	{0x07, 0x1B, 0x11, 0x3B, 0x0C, 0xA7, 0x43, 0xFE, 0xCC, 0xCF, 0x3D, 0x05,
	 0x1F, 0x73, 0x73, 0x82},
	/* 60 bytes */
	{0xAD, 0x7A, 0x2B, 0xD0, 0x3E, 0xAC, 0x83, 0x5A, 0x6F, 0x62, 0x0F, 0xDC,
	 0xB5, 0x06, 0xB3, 0x45},
	/* 60 bytes */
	{0x01, 0x3F, 0xE0, 0x0B, 0x5F, 0x11, 0xBE, 0x7F, 0x86, 0x6D, 0x0C, 0xBB,
	 0xC5, 0x5A, 0x7A, 0x90},
	/* 75 bytes */
	{0x88, 0xEE, 0x08, 0x7F, 0xD9, 0x5D, 0xA9, 0xFB, 0xF6, 0x72, 0x5A, 0xA9,
	 0xD7, 0x57, 0xB0, 0xCD},
	/* gmac - only authentication */
	/* 54 bytes */
	{0xAD, 0x7A, 0x2B, 0xD0, 0x3E, 0xAC, 0x83, 0x5A, 0x6F, 0x62, 0x0F, 0xDC,
	 0xB5, 0x06, 0xB3, 0x45},
	/* 60 bytes */
	{0x07, 0x1B, 0x11, 0x3B, 0x0C, 0xA7, 0x43, 0xFE, 0xCC, 0xCF, 0x3D, 0x05,
	 0x1F, 0x73, 0x73, 0x82},
	/* 65 bytes */
	{0x01, 0x3F, 0xE0, 0x0B, 0x5F, 0x11, 0xBE, 0x7F, 0x86, 0x6D, 0x0C, 0xBB,
	 0xC5, 0x5A, 0x7A, 0x90},
	/* 79 bytes */
	{0x88, 0xEE, 0x08, 0x7F, 0xD9, 0x5D, 0xA9, 0xFB, 0xF6, 0x72, 0x5A, 0xA9,
	 0xD7, 0x57, 0xB0, 0xCD}
};

static uint64_t macsec_reference_iv_sci[] = {
	/* gcm - encryption and authentication */
	/* 54 bytes */
	0xF0761E8DCD3D0001ull,
	/* 60 bytes */
	0x12153524C0895E81ull,
	/* 60 bytes */
	0x7CFDE9F9E33724C6ull,
	/* 75 bytes */
	0x7AE8E2CA4EC50001ull,
	/* gmac - only authentication */
	/* 54 bytes */
	0x12153524C0895E81ull,
	/* 60 bytes */
	0xF0761E8DCD3D0001ull,
	/* 65 bytes */
	0x7CFDE9F9E33724C6ull,
	/* 79 bytes */
	0x7AE8E2CA4EC50001ull
};


static uint32_t macsec_reference_iv_pn[] = {
	/* gcm - encryption and authentication */
	/* 54 bytes */
	0x76D457ED,
	/* 60 bytes */
	0xB2C28465,
	/* 61 bytes */
	0x8932D612,
	/* 75 bytes */
	0x2E58495C,
	/*gmac - only authentication */
	/* 54 bytes */
	0xB2C28465,
	/* 60 bytes */
	0x76D457ED,
	/* 65 bytes */
	0x8932D612,
	/* 79 bytes */
	0x2E58495C
};

static uint8_t macsec_reference_sectag_tcian[] = {
	/* gcm - encryption and authentication */
	/* 54 bytes */
	0x4C,
	/* 60 bytes */
	0x2E,
	/* 61 bytes */
	0x2F,
	/* 75 bytes */
	0x4D,
	/*gmac - only authentication */
	/* 54 bytes */
	0x22, /* E bit = 0, no encrypt */
	/* 60 bytes */
	0x40,
	/* 65 bytes */
	0x23,
	/* 79 bytes */
	0x41
};

static uint16_t macsec_reference_sectag_etype[] = {
	/* gcm - encryption and authentication */
	/* 54 bytes */
	0x88E5,
	/* 60 bytes */
	0x88E5,
	/* 61 bytes */
	0x88E5,
	/* 75 bytes */
	0x88E5,
	/*gmac - only authentication */
	/* 54 bytes */
	0x88E5,
	/* 60 bytes */
	0x88E5,
	/* 65 bytes */
	0x88E5,
	/* 79 bytes */
	0x88E5
};

/** length in bits */
static uint32_t macsec_reference_length[] = {
	432, 480, 488, 600, 432, 480, 520, 632
};

static uint8_t macsec_reference_plaintext[][MACSEC_MAX_TEST_PLAIN_PACKET_SIZE] = {
	/* gcm - encryption and authentication */
	/* 54 bytes */
	{0xE2, 0x01, 0x06, 0xD7, 0xCD, 0x0D, 0xF0, 0x76, 0x1E, 0x8D, 0xCD, 0x3D,
	 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
	 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	 0x31, 0x32, 0x33, 0x34, 0x00, 0x04},
	/* 60 bytes */
	{0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63, 0x7A, 0x0D, 0x46, 0xDF, 0x99, 0x8D,
	 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
	 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x00,
	 0x02},
	/* 61 bytes */
	{0x84, 0xC5, 0xD5, 0x13, 0xD2, 0xAA, 0xF6, 0xE5, 0xBB, 0xD2, 0x72, 0x77,
	 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
	 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x00,
	 0x06},
	/* 75 bytes */
	{0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5,
	 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
	 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
	 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	 0x49, 0x00, 0x08},
	/* gmac - only authentication */
	/* 54 bytes */
	{0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63, 0x7A, 0x0D, 0x46, 0xDF, 0x99, 0x8D,
	 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
	 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	 0x31, 0x32, 0x33, 0x34, 0x00, 0x01},
	/* 60 bytes */
	{0xE2, 0x01, 0x06, 0xD7, 0xCD, 0x0D, 0xF0, 0x76, 0x1E, 0x8D, 0xCD, 0x3D,
	 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
	 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x00, 0x03
	},
	/* 65 bytes */
	{0x84, 0xC5, 0xD5, 0x13, 0xD2, 0xAA, 0xF6, 0xE5, 0xBB, 0xD2, 0x72, 0x77,
	 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
	 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
	 0x3D, 0x3E, 0x3F, 0x00, 0x05},
	 /* 79 bytes */
	{0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5,
	 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
	 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
	 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x00, 0x07}
};

static uint8_t macsec_reference_ciphertext[][MACSEC_MAX_TEST_ENCRYPT_PACKET_SIZE] = {
	/* gcm - encryption and authentication */
	/* 54 bytes */
	{0xE2, 0x01, 0x06, 0xD7, 0xCD, 0x0D, 0xF0, 0x76, 0x1E, 0x8D, 0xCD, 0x3D,
	 0x88, 0xE5, 0x4C, 0x2A, 0x76, 0xD4, 0x57, 0xED, 0x13, 0xB4, 0xC7, 0x2B,
	 0x38, 0x9D, 0xC5, 0x01, 0x8E, 0x72, 0xA1, 0x71, 0xDD, 0x85, 0xA5, 0xD3,
	 0x75, 0x22, 0x74, 0xD3, 0xA0, 0x19, 0xFB, 0xCA, 0xED, 0x09, 0xA4, 0x25,
	 0xCD, 0x9B, 0x2E, 0x1C, 0x9B, 0x72, 0xEE, 0xE7, 0xC9, 0xDE, 0x7D, 0x52,
	 0xB3, 0xF3, 0xD6, 0xA5, 0x28, 0x4F, 0x4A, 0x6D, 0x3F, 0xE2, 0x2A, 0x5D,
	 0x6C, 0x2B, 0x96, 0x04, 0x94, 0xC3},
	/* 60 bytes */
	{0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63, 0x7A, 0x0D, 0x46, 0xDF, 0x99, 0x8D,
	 0x88, 0xE5, 0x2E, 0x00, 0xB2, 0xC2, 0x84, 0x65, 0x12, 0x15, 0x35, 0x24,
	 0xC0, 0x89, 0x5E, 0x81, 0x70, 0x1A, 0xFA, 0x1C, 0xC0, 0x39, 0xC0, 0xD7,
	 0x65, 0x12, 0x8A, 0x66, 0x5D, 0xAB, 0x69, 0x24, 0x38, 0x99, 0xBF, 0x73,
	 0x18, 0xCC, 0xDC, 0x81, 0xC9, 0x93, 0x1D, 0xA1, 0x7F, 0xBE, 0x8E, 0xDD,
	 0x7D, 0x17, 0xCB, 0x8B, 0x4C, 0x26, 0xFC, 0x81, 0xE3, 0x28, 0x4F, 0x2B,
	 0x7F, 0xBA, 0x71, 0x3D, 0x4F, 0x8D, 0x55, 0xE7, 0xD3, 0xF0, 0x6F, 0xD5,
	 0xA1, 0x3C, 0x0C, 0x29, 0xB9, 0xD5, 0xB8, 0x80},
	/* 61 bytes */
	{0x84, 0xC5, 0xD5, 0x13, 0xD2, 0xAA, 0xF6, 0xE5, 0xBB, 0xD2, 0x72, 0x77,
	 0x88, 0xE5, 0x2F, 0x00, 0x89, 0x32, 0xD6, 0x12, 0x7C, 0xFD, 0xE9, 0xF9,
	 0xE3, 0x37, 0x24, 0xC6, 0x3A, 0x4D, 0xE6, 0xFA, 0x32, 0x19, 0x10, 0x14,
	 0xDB, 0xB3, 0x03, 0xD9, 0x2E, 0xE3, 0xA9, 0xE8, 0xA1, 0xB5, 0x99, 0xC1,
	 0x4D, 0x22, 0xFB, 0x08, 0x00, 0x96, 0xE1, 0x38, 0x11, 0x81, 0x6A, 0x3C,
	 0x9C, 0x9B, 0xCF, 0x7C, 0x1B, 0x9B, 0x96, 0xDA, 0x80, 0x92, 0x04, 0xE2,
	 0x9D, 0x0E, 0x2A, 0x76, 0x42, 0xBF, 0xD3, 0x10, 0xA4, 0x83, 0x7C, 0x81,
	 0x6C, 0xCF, 0xA5, 0xAC, 0x23, 0xAB, 0x00, 0x39, 0x88},
	/* 75 bytes */
	{0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5,
	 0x88, 0xE5, 0x4D, 0x00, 0x2E, 0x58, 0x49, 0x5C, 0xC3, 0x1F, 0x53, 0xD9,
	 0x9E, 0x56, 0x87, 0xF7, 0x36, 0x51, 0x19, 0xB8, 0x32, 0xD2, 0xAA, 0xE7,
	 0x07, 0x41, 0xD5, 0x93, 0xF1, 0xF9, 0xE2, 0xAB, 0x34, 0x55, 0x77, 0x9B,
	 0x07, 0x8E, 0xB8, 0xFE, 0xAC, 0xDF, 0xEC, 0x1F, 0x8E, 0x3E, 0x52, 0x77,
	 0xF8, 0x18, 0x0B, 0x43, 0x36, 0x1F, 0x65, 0x12, 0xAD, 0xB1, 0x6D, 0x2E,
	 0x38, 0x54, 0x8A, 0x2C, 0x71, 0x9D, 0xBA, 0x72, 0x28, 0xD8, 0x40, 0x88,
	 0xF8, 0x75, 0x7A, 0xDB, 0x8A, 0xA7, 0x88, 0xD8, 0xF6, 0x5A, 0xD6, 0x68,
	 0xBE, 0x70, 0xE7},
	/* gmac - only authentication */
	/* 54 bytes */
	{0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63, 0x7A, 0x0D, 0x46, 0xDF, 0x99, 0x8D,
	 0x88, 0xE5, 0x22, 0x2A, 0xB2, 0xC2, 0x84, 0x65, 0x12, 0x15, 0x35, 0x24,
	 0xC0, 0x89, 0x5E, 0x81, 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
	 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
	 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x00, 0x01, 0xF0, 0x94,
	 0x78, 0xA9, 0xB0, 0x90, 0x07, 0xD0, 0x6F, 0x46, 0xE9, 0xB6, 0xA1, 0xDA,
	 0x25, 0xDD},
	/* 60 bytes */
	{0xE2, 0x01, 0x06, 0xD7, 0xCD, 0x0D, 0xF0, 0x76, 0x1E, 0x8D, 0xCD, 0x3D,
	 0x88, 0xE5, 0x40, 0x00, 0x76, 0xD4, 0x57, 0xED, 0x08, 0x00, 0x0F, 0x10,
	 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
	 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
	 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x00, 0x03, 0x0C, 0x01, 0x7B, 0xC7,
	 0x3B, 0x22, 0x7D, 0xFC, 0xC9, 0xBA, 0xFA, 0x1C, 0x41, 0xAC, 0xC3, 0x53
	},
	/* 65 bytes */
	{0x84, 0xC5, 0xD5, 0x13, 0xD2, 0xAA, 0xF6, 0xE5, 0xBB, 0xD2, 0x72, 0x77,
	 0x88, 0xE5, 0x23, 0x00, 0x89, 0x32, 0xD6, 0x12, 0x7C, 0xFD, 0xE9, 0xF9,
	 0xE3, 0x37, 0x24, 0xC6, 0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
	 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
	 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x00, 0x05, 0x21, 0x78, 0x67,
	 0xe5, 0x0c, 0x2d, 0xad, 0x74, 0xc2, 0x8c, 0x3b, 0x50, 0xab, 0xdf, 0x69,
	 0x5a},
	/* 79 bytes */
	{0x68, 0xF2, 0xE7, 0x76, 0x96, 0xCE, 0x7A, 0xE8, 0xE2, 0xCA, 0x4E, 0xC5,
	 0x88, 0xE5, 0x41, 0x00, 0x2E, 0x58, 0x49, 0x5C, 0x08, 0x00, 0x0F, 0x10,
	 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
	 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
	 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
	 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
	 0x4D, 0x00, 0x07, 0x07, 0x92, 0x2B, 0x8E, 0xBC, 0xF1, 0x0B, 0xB2, 0x29,
	 0x75, 0x88, 0xCA, 0x4C, 0x61, 0x45, 0x23}
};

#endif /* MACSEC_TEST_VECTOR_H_ */
