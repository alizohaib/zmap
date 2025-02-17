/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdint.h>
#include <assert.h>
#include "../lib/rijndael-alg-fst.h"
#include "../lib/random.h"
#include "../lib/logger.h"
#include "validate.h"

#define AES_ROUNDS 10
#define AES_BLOCK_WORDS 4
#define AES_KEY_BYTES 16

static int inited = 0;
static uint32_t aes_sched[(AES_ROUNDS + 1) * 4];

void validate_init()
{
	uint8_t key[AES_KEY_BYTES];
	if (!random_bytes(key, AES_KEY_BYTES)) {
		log_fatal("validate", "couldn't get random bytes");
	}
	if (rijndaelKeySetupEnc(aes_sched, key, AES_KEY_BYTES * 8) != AES_ROUNDS) {
		log_fatal("validate", "couldn't initialize AES key");
	}
	inited = 1;
}

void validate_gen(const uint32_t src, const uint32_t dst,
		  uint8_t output[VALIDATE_BYTES])
{
	validate_gen_ex(src, dst, 0, 0, output);
}

void validate_gen_ex(const uint32_t input0, const uint32_t input1,
		     const uint32_t input2, const uint32_t input3,
		     uint8_t output[VALIDATE_BYTES])
{
	assert(inited);

	uint32_t aes_input[AES_BLOCK_WORDS];
	aes_input[0] = input0;
	aes_input[1] = input1;
	aes_input[2] = input2;
	aes_input[3] = input3;
	rijndaelEncrypt(aes_sched, AES_ROUNDS, (uint8_t *)aes_input, output);
}

void validate_gen_ipv6(const struct in6_addr *src, const struct in6_addr *dst,
				uint8_t output[VALIDATE_BYTES])
{
	assert(inited);

	uint32_t aes_input[AES_BLOCK_WORDS];
	for (int i = 0; i < AES_BLOCK_WORDS; i++) {
		// XOR IPv6 src and dst
		aes_input[i] = ((uint32_t *) src)[i] ^ ((uint32_t *) dst)[i];
	}
	rijndaelEncrypt(aes_sched, AES_ROUNDS, (uint8_t *)aes_input, output);
}
