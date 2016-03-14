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
#include "aead.h"
#include "aead_test_vector.h"

/* Forward declarations */
static error_t parse_opts(int, char *, struct argp_state *);
static void unregister_aead(struct protocol_info *);

struct argp_option aead_options[] = {
	{"cipheralg", 'h', "CIPHER", 0,
	 "Ciphering algorithm:\n"
	 "0 = 3DES\n"},
	{"intalg", 'q', "INTEGRITY", 0,
	 "Integrity algorithm:\n"
	 "0 = HMAC_MD5_96\n"},
	{0}
};

/* Parser for aead command line options */
static struct argp aead_argp = {
	aead_options, parse_opts
};

static struct argp_child argp_children = {
	&aead_argp , 0, "AEAD protocol options", 0};

static void set_enc_buf_cb(struct qm_fd *fd, uint8_t *buf,
			   struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct aead_ref_vector_s *rtv = proto->proto_vector;
	struct qm_sg_entry *sg_in, *sg_out;
	struct qm_sg_entry *sgs_in;
	dma_addr_t addr;
	static uint8_t plain_data;
	uint8_t *in_buf;
	int i;

	addr = qm_fd_addr(fd);

	sg_out = __dma_mem_ptov(addr);
	sg_in = sg_out + 1;

	sgs_in = (struct qm_sg_entry *)buf;
	in_buf = buf + SG_IN_ENTRIES * sizeof(struct qm_sg_entry);

	sg_in->extension = 1;
	qm_sg_entry_set64(&sgs_in[0], rtv->iv_phys);
	sgs_in[0].length = rtv->ivlen;

	qm_sg_entry_set64(&sgs_in[1], rtv->seq_spi_phys);
	sgs_in[1].length = SPI_SIZE + SEQNUM_SIZE;

	qm_sg_entry_set64(&sgs_in[2], rtv->iv_phys);
	sgs_in[2].length = rtv->ivlen;

	qm_sg_entry_set64(&sgs_in[3], qm_sg_entry_get64(sg_in) +
				SG_IN_ENTRIES * sizeof(struct qm_sg_entry));
	sgs_in[3].length = crypto_info->buf_size;
	sgs_in[3].final = 1;

	sg_in->length = rtv->ivlen + rtv->auth_only_len + crypto_info->buf_size;

	fd->cmd = rtv->fd_cmd;

	if (CIPHER == crypto_info->mode)
		memcpy(in_buf, rtv->plaintext, crypto_info->buf_size);
	else
		for (i = 0; i < crypto_info->buf_size; i++)
			in_buf[i] = plain_data++;
}

static void set_dec_buf_cb(struct qm_fd *fd, uint8_t *buf,
			   struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct aead_ref_vector_s *rtv = proto->proto_vector;
	struct qm_sg_entry *sg_in, *sg_out;
	struct qm_sg_entry *sgs_in;
	dma_addr_t addr;

	addr = qm_fd_addr(fd);

	/*
	 * For decryption, one needs to switch the corresponding
	 * SG entry in the input buffer such that it points to the
	 * encrypted buffer. Also, the length needs to be updated, both
	 * in the corresponding SG entry, as well as the input SG entry
	 * of the FD
	 */
	sg_out = __dma_mem_ptov(addr);
	sg_in = sg_out + 1;

	addr = qm_sg_entry_get64(sg_out);
	sgs_in = (struct qm_sg_entry *)__dma_mem_ptov(addr);

	/*
	 * Store the address of plaintext buffer; here the decrypted buffer
	 * will be stored
	 */
	addr = qm_sg_entry_get64(&sgs_in[3]);

	sg_in->extension = 1;

	/* Switch the plaintext buffer with the encrypted buffer */
	qm_sg_entry_set64(&sgs_in[3], qm_sg_entry_get64(sg_in));
	/*
	 * Update the length of the entry to be equal to the length of the
	 * encrypted buffer + ICV
	 */
	sgs_in[3].length = sg_in->length;
	/* Update the total length */
	sg_in->length += rtv->ivlen + rtv->auth_only_len;

	qm_sg_entry_set64(sg_in, qm_sg_entry_get64(sg_out));

	/* Set the output to point to the old plaintext buffer */
	qm_sg_entry_set64(sg_out, addr);

	/* Clear the extension bit */
	sg_out->extension = 0;
	/* Set the proper length */
	sg_out->length = crypto_info->buf_size;

	fd->cmd = rtv->fd_cmd;
}

static int init_ref_test_vector_aead(struct test_param *crypto_info)
{
	int i;
	struct protocol_info *proto = crypto_info->proto;
	struct aead_params *aead_params = proto->proto_params;
	struct aead_ref_vector_s *rtv = proto->proto_vector;

	int test_offset = -1;

	for (i = 0; i < AEAD_TEST_ARRAY_OFFSET(aead_params); i++)
		test_offset += aead_test_num_tests[i];

	test_offset += crypto_info->test_set;

	rtv->auth_key = (uintptr_t)aead_test_auth_key[test_offset];
	rtv->auth_keylen = aead_test_auth_keylen[test_offset];

	rtv->key = (uintptr_t)aead_test_cipher_key[test_offset];
	rtv->cipher_keylen = aead_test_cipher_keylen[test_offset];

	rtv->ivlen = aead_test_ivlen[test_offset];
	rtv->icv_size = aead_test_icv_size[test_offset];

	rtv->iv = __dma_mem_memalign(L1_CACHE_BYTES, rtv->ivlen);
	if (!rtv->iv) {
		pr_err("Not enough memory to allocate IV");
		return -ENOMEM;
	}
	rtv->iv_phys = __dma_mem_vtop(rtv->iv);

	rtv->seq_spi = __dma_mem_memalign(L1_CACHE_BYTES,
					  SPI_SIZE + SEQNUM_SIZE);
	if (!rtv->seq_spi) {
		pr_err("Not enough memory to allocate SN & SPI");
		return -ENOMEM;
	}
	rtv->seq_spi_phys = __dma_mem_vtop(rtv->seq_spi);

	rtv->auth_only_len = aead_test_auth_only_len[test_offset];

	if (CIPHER == crypto_info->mode) {
		memcpy(rtv->iv, aead_test_data_iv[test_offset], rtv->ivlen);
		memcpy(rtv->seq_spi, &aead_test_data_spi[test_offset],
		       SPI_SIZE);
		memcpy(rtv->seq_spi + SPI_SIZE,
		       &aead_test_data_seq_no[test_offset], SEQNUM_SIZE);

		rtv->length = NO_OF_BITS(aead_test_data_in_len[test_offset]);
		rtv->plaintext = aead_test_data_in[test_offset];
		rtv->ciphertext = aead_test_data_out[test_offset];
	} else {
		for (i = 0; i < rtv->ivlen; i++)
			rtv->iv[i] = i;
		for (i = 0; i < SPI_SIZE + SEQNUM_SIZE; i++)
			rtv->seq_spi[i] = i;
	}

	rtv->fd_cmd = aead_test_set_cmd[test_offset];
	rtv->initial_auth_only_len =
			aead_test_initial_auth_only_len[test_offset];
	return 0;
}

static void *create_descriptor(bool mode, void *params)
{
	struct test_param *crypto_info = (struct test_param *)params;
	struct protocol_info *proto = crypto_info->proto;
	struct aead_ref_vector_s *rtv = proto->proto_vector;
	struct sec_descriptor_t *prehdr_desc;
	struct alginfo cipher_info, auth_info;
	uint32_t *shared_desc = NULL;
	int i, shared_desc_len = 0;
	bool found = false;

	prehdr_desc = __dma_mem_memalign(L1_CACHE_BYTES,
					 sizeof(struct sec_descriptor_t));
	if (unlikely(!prehdr_desc)) {
		fprintf(stderr,
			"error: %s: dma_mem_memalign failed for preheader\n",
			__func__);
		return NULL;
	}

	/* Store the pointer to the descriptor for freeing later on */
	for (i = mode ? 0 : 1; i < proto->num_cpus * FQ_PER_CORE * 2; i += 2) {
		mutex_lock(&proto->desc_wlock);
		if (proto->descr[i].descr == NULL) {
			proto->descr[i].descr = (uint32_t *)prehdr_desc;
			proto->descr[i].mode = mode;
			found = true;
			mutex_unlock(&proto->desc_wlock);
			break;
		}
		mutex_unlock(&proto->desc_wlock);
	}

	if (!found) {
		pr_err("Could not store descriptor pointer %s\n", __func__);
		return NULL;
	}

	memset(prehdr_desc, 0, sizeof(struct sec_descriptor_t));
	shared_desc = (typeof(shared_desc))&prehdr_desc->descbuf;

	switch (rtv->cipher_alg) {
	case AEAD_CIPHER_TYPE_TDES:
		cipher_info.algtype = OP_ALG_ALGSEL_3DES;
		break;

	default:
		pr_err("Invalid cipher algorithm selected");
		return NULL;
	}

	switch (rtv->auth_alg) {
	case AEAD_AUTH_TYPE_HMAC_MD5_96:
		auth_info.algtype = OP_ALG_ALGSEL_MD5;
		break;

	default:
		pr_err("Invalid integrity algorithm selected");
		return NULL;
	}

	cipher_info.algmode = OP_ALG_AAI_CBC;
	cipher_info.key = rtv->key;
	cipher_info.keylen = rtv->cipher_keylen;
	cipher_info.key_enc_flags = 0;
	cipher_info.key_type = RTA_DATA_IMM;

	auth_info.key = rtv->auth_key;
	auth_info.keylen = rtv->auth_keylen;
	auth_info.key_enc_flags = 0;
	auth_info.key_type = RTA_DATA_IMM;

	shared_desc_len = cnstr_shdsc_authenc(shared_desc,
					      true,
					      SWAP_DESCRIPTOR,
					      &cipher_info,
					      &auth_info,
					      rtv->ivlen,
					      rtv->initial_auth_only_len,
					      rtv->icv_size,
					      ENCRYPT == mode ?
							DIR_ENC : DIR_DEC);

	prehdr_desc->prehdr.hi.word = shared_desc_len & SEC_PREHDR_SDLEN_MASK;

	pr_debug("SEC %s shared descriptor:\n", proto->name);

	for (i = 0; i < shared_desc_len; i++)
		pr_debug("0x%x\n", *shared_desc++);

	return prehdr_desc;
}

/**
 * @brief      Parse aead related command line options
 *
 */
static error_t parse_opts(int key, char *arg, struct argp_state *state)
{
	struct parse_input_t *input = state->input;
	uint32_t *p_proto_params = input->proto_params;
	struct test_param *crypto_info = input->crypto_info;
	struct aead_params *aead_params;

	/*
	 * If the protocol was not selected, then it makes no sense to go
	 * further.
	 */
	if (!crypto_info->proto)
		return 0;

	aead_params = crypto_info->proto->proto_params;
	switch (key) {
	case 'h':
		aead_params->c_alg = atoi(arg);
		*p_proto_params |= BMASK_AEAD_CIPHER;
		fprintf(stdout, "AEAD cipher algorithm = %d\n",
			aead_params->c_alg);
		break;
	case 'q':
		aead_params->i_alg = atoi(arg);
		*p_proto_params |= BMASK_AEAD_INTEGRITY;
		fprintf(stdout, "AEAD integrity algorithm = %d\n",
			aead_params->i_alg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/**
 * @brief       Check SEC parameters provided by user for aead are valid
 *              or not.
 * @param[in]   g_proto_params - Bit mask of the optional parameters provided
 *              by user
 * @param[in]   crypto_info - test parameters
 * @return      0 on success, otherwise -EINVAL value
 */
static int validate_opts(uint32_t g_proto_params,
			 struct test_param *crypto_info)
{
	struct aead_params *aead_params = crypto_info->proto->proto_params;

	if (BMASK_AEAD_VALID ^ g_proto_params) {
		fprintf(stderr,
			"error: aead Invalid Parameters\n"
			"see --help option\n");
		return -EINVAL;
	}

	switch (aead_params->c_alg) {
	case AEAD_CIPHER_TYPE_TDES:
		break;
	default:
		fprintf(stderr,
			"error: aead Invalid Parameters: Invalid cipher algorithm\n"
			"see --help option\n");
		return -EINVAL;
	}

	switch (aead_params->i_alg) {
	case AEAD_AUTH_TYPE_HMAC_MD5_96:
		break;
	default:
		fprintf(stderr,
			"error: aead Invalid Parameters: Invalid integrity algorithm\n"
			"see --help option\n");
		return -EINVAL;
	}

	return 0;
}

static int get_buf_size(struct test_param *crypto_info)
{
	struct aead_ref_vector_s *rtv = crypto_info->proto->proto_vector;

	return 2 * crypto_info->buf_size + rtv->icv_size;
}

/**
 * @brief       Set buffer sizes for input/output frames
 * @param[in]   crypto_info - test parameters
 * @return      0 on success
 */
static int set_buf_size(struct test_param *crypto_info)
{
	struct aead_ref_vector_s *rtv = crypto_info->proto->proto_vector;
	struct runtime_param *p_rt = &(crypto_info->rt);

	p_rt->input_buf_length = crypto_info->buf_size;
	p_rt->input_buf_capacity = crypto_info->buf_size +
				SG_IN_ENTRIES * sizeof(struct qm_sg_entry);
	p_rt->output_buf_size = crypto_info->buf_size + rtv->icv_size;

	return 0;
}

/**
 * @brief       Verifies if user gave a correct test set
 * @param[in]   crypto_info - test parameters
 * @return      0 on success, otherwise -EINVAL value
 */
static int validate_test_set(struct test_param *crypto_info)
{
	struct protocol_info *proto = crypto_info->proto;
	struct aead_params *aead_params = proto->proto_params;
	const int proto_offset = AEAD_TEST_ARRAY_OFFSET(aead_params);

	if (crypto_info->test_set <= aead_test_num_tests[proto_offset])
		return 0;

	fprintf(stderr,
		"error: Invalid Parameters: Test set number is invalid\n");
	return -EINVAL;
}

/**
 * @brief       Allocates the necessary structures for a protocol, sets the
 *              callbacks for the protocol and returns the allocated chunk.
 * @return      NULL if an error occurred, pointer to the protocol structure
 *              otherwise.
 */
struct protocol_info *register_aead(void)
{
	unsigned num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct protocol_info *proto_info = calloc(1, sizeof(*proto_info));

	if (unlikely(!proto_info)) {
		pr_err("failed to allocate protocol structure in %s",
		       __FILE__);
		return NULL;
	}

	SAFE_STRNCPY(proto_info->name, "AEAD", sizeof(proto_info->name));
	proto_info->unregister = unregister_aead;
	proto_info->argp_children = &argp_children;
	proto_info->init_ref_test_vector = init_ref_test_vector_aead;
	proto_info->set_enc_buf_cb = set_enc_buf_cb;
	proto_info->set_dec_buf_cb = set_dec_buf_cb;
	proto_info->setup_sec_descriptor = create_descriptor;
	proto_info->validate_opts = validate_opts;
	proto_info->get_buf_size = get_buf_size;
	proto_info->set_buf_size = set_buf_size;
	proto_info->validate_test_set = validate_test_set;

	proto_info->proto_params = calloc(1, sizeof(struct aead_params));
	if (unlikely(!proto_info->proto_params)) {
		pr_err("failed to allocate protocol parameters in %s",
		       __FILE__);
		goto err;
	}

	proto_info->proto_vector = calloc(1, sizeof(struct aead_ref_vector_s));
	if (unlikely(!proto_info->proto_vector)) {
		pr_err("failed to allocate protocol test vector in %s",
		       __FILE__);
		goto err;
	}

	/*
	 * For each "to SEC" FQ, there is one descriptor
	 * There are FQ_PER_CORE descriptors per core
	 * There is one descriptor for each "direction" (enc/dec).
	 * Thus the total number of descriptors that need to be stored across
	 * the whole system is:
	 *                       num_desc = num_cpus * FQ_PER_CORE * 2
	 * Note: This assumes that all the CPUs are used; if not all CPUs are
	 *       used, some memory will be wasted (equal to the # of unused
	 *       cores multiplied by sizeof(struct desc_storage))
	 */
	proto_info->descr = calloc(num_cpus * FQ_PER_CORE * 2,
				   sizeof(struct desc_storage));
	if (unlikely(!proto_info->descr)) {
		pr_err("failed to allocate descriptor storage in %s",
		       __FILE__);
		goto err;
	}
	mutex_init(&proto_info->desc_wlock);
	proto_info->num_cpus = num_cpus;

	return proto_info;
err:
	free(proto_info->proto_params);
	free(proto_info->proto_vector);
	free(proto_info);
	return NULL;
}

/**
 * @brief       Deallocates the structures for a protocol (allocated on
 *              registration) and frees any other memory that was allocated
 *              during the protocol processing.
 * @param[in]   proto_info - protocol parameters
 * @return      None
 *
 */
void unregister_aead(struct protocol_info *proto_info)
{
	int i;
	struct aead_ref_vector_s *rtv;

	if (!proto_info)
		return;

	rtv = proto_info->proto_vector;
	for (i = 0; i < proto_info->num_cpus * FQ_PER_CORE * 2; i++)
		if (proto_info->descr[i].descr)
			__dma_mem_free(proto_info->descr[i].descr);

	__dma_mem_free(rtv->iv);
	__dma_mem_free(rtv->seq_spi);

	free(proto_info->proto_vector);
	free(proto_info->proto_params);
	free(proto_info);
}
