/*
 * Copyright 2012-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "fops.h"

static const unsigned char aes_key[] = {
	0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
	0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
	0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char aes_iv[] = {
	0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

int pad_len;

FOPS_TYPE input;
FOPS_TYPE cipher;
FOPS_TYPE plaintext;

void encrypt_aes_256_cbc(void)
{
	EVP_CIPHER_CTX *ctx;

	// https://stackoverflow.com/questions/3283787/size-of-data-after-aes-cbc-and-aes-ecb-encryption#3284136
	pad_len = AES_BLOCK_SIZE - input.length % AES_BLOCK_SIZE;
	cipher.length = input.length + pad_len;

	cipher.data = (unsigned char *) malloc(sizeof(unsigned char)*cipher.length);
	cipher.in_use = 1;

	printf("AES 256 CBC Encrypt:\nPlaintext:\n");
	BIO_dump_fp(stdout, (const char*) input.data, input.length);

	// Create cipher ctx, set algo, iv and key
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);
	EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, aes_iv);

	/* Encrypt plaintext */
	EVP_EncryptUpdate(ctx, cipher.data, (int*)&cipher.length, input.data, input.length);

	printf("\nCiphertext wo padding:\n");
	BIO_dump_fp(stdout, (const char*) cipher.data, cipher.length);

	/* Finalise: */
	int tmp_len;
	EVP_EncryptFinal_ex(ctx, cipher.data + cipher.length, &tmp_len);
	cipher.length += tmp_len;

	/* Output encrypted block */
	printf("Ciphertext with padding:\n");
	BIO_dump_fp(stdout, (const char*) cipher.data, cipher.length);

	EVP_CIPHER_CTX_free(ctx);
	printf("\n\n");
}

void decrypt_aes_256_cbc(void)
{
	EVP_CIPHER_CTX *ctx;

	plaintext.length = cipher.length;
	plaintext.data = (unsigned char *) malloc(sizeof(unsigned char) * plaintext.length);
	plaintext.in_use = 1;

	printf("AES 256 CBC Derypt:\nCiphertext:\n");
	BIO_dump_fp(stdout, (const char*) cipher.data, cipher.length);

	// Create cipher ctx, set algo, iv and key
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL);
	EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, aes_iv);

	/* Decrypt plaintext */
	EVP_DecryptUpdate(ctx, plaintext.data, (int*)&plaintext.length, cipher.data, cipher.length);

	printf("\nPlaintext before final:\n");
	BIO_dump_fp(stdout, (const char*) plaintext.data, plaintext.length);

	int tmp_len;
	EVP_DecryptFinal_ex(ctx, plaintext.data + plaintext.length, &tmp_len);
	plaintext.length += tmp_len;

	/* Output decrypted block */
	printf("Plaintext after final:\n");
	BIO_dump_fp(stdout, (const char*) plaintext.data, plaintext.length);

	EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char **argv)
{
	input = fops_read("/tmp/rm.txt");
	encrypt_aes_256_cbc();
	decrypt_aes_256_cbc();
	fops_write("/tmp/op.txt", plaintext);

	fops_clear(cipher);
	fops_clear(plaintext);
}
