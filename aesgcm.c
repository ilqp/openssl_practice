/*
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GCM test program, uses the same NIST data used for the FIPS
 * self test but uses the application level EVP APIs.
 */
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "fops.h"

/* AES-GCM test data from NIST public test vectors */

static const unsigned char gcm_key[] = {
	0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
	0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
	0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] = {
	0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

static const unsigned char gcm_aad[] = {
	0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
	0x7f, 0xec, 0x78, 0xde
};

unsigned char *cipher_buffer;
unsigned char *plain_buffer;
unsigned char tag_buffer[16];
int cipher_len, plain_len, tag_len;
FOPS_TYPE input;

void aes_gcm_encrypt(void)
{
	EVP_CIPHER_CTX *ctx;
	int outlen, tmplen;
	unsigned char outbuf[1024];

	cipher_buffer = (unsigned char *) malloc(sizeof(unsigned char)*input.length);

	printf("AES GCM Encrypt:\nPlaintext:\n");
	BIO_dump_fp(stdout, (const char*) input.data, input.length);

	// Create cipher ctx, set algo, iv and key
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
	EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);

	/* Zero or more calls to specify any AAD */
	EVP_EncryptUpdate(ctx, NULL, &cipher_len, gcm_aad, sizeof(gcm_aad));

	/* Encrypt plaintext */
	EVP_EncryptUpdate(ctx, cipher_buffer, &cipher_len, input.data, input.length);

	/* Output encrypted block */
	printf("Ciphertext:\n");
	BIO_dump_fp(stdout, (const char*) cipher_buffer, cipher_len);

	/* Finalise: note get no output for GCM */
	EVP_EncryptFinal_ex(ctx, tag_buffer, &tag_len);

	/* Get tag */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag_buffer);
	tag_len = 16;

	/* Output tag */
	printf("Tag:\n");
	BIO_dump_fp(stdout, (const char*) tag_buffer, tag_len);
	EVP_CIPHER_CTX_free(ctx);
}

void aes_gcm_decrypt(void)
{
	EVP_CIPHER_CTX *ctx;
	int outlen, tmplen, rv;
	unsigned char outbuf[1024];

	plain_buffer = (unsigned char *) malloc(sizeof(unsigned char)*input.length);

	printf("AES GCM Derypt:\nCiphertext:\n");
	BIO_dump_fp(stdout, (const char*) cipher_buffer, cipher_len);

	// Create cipher ctx, set algo, iv and key
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gcm_iv), NULL);
	EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);

	/* Zero or more calls to specify any AAD */
	EVP_DecryptUpdate(ctx, NULL, &plain_len, gcm_aad, sizeof(gcm_aad));

	/* Decrypt plaintext */
	EVP_DecryptUpdate(ctx, plain_buffer, &plain_len, cipher_buffer, cipher_len);

	/* Output decrypted block */
	printf("Plaintext:\n");
	BIO_dump_fp(stdout, (const char*) plain_buffer, plain_len);

	/* Set expected tag value. */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, (void *)tag_buffer);

	/* Finalise: note get no output for GCM */
	rv = EVP_DecryptFinal_ex(ctx, plain_buffer, &plain_len);
	/* Print out return value. If this is not successful authentication failed and plaintext is not trustworthy. */
	printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
	EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char **argv)
{
	input = fops_read("/tmp/rm.txt");
	aes_gcm_encrypt();
	aes_gcm_decrypt();
}
