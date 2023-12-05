// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (c) 2023 Cryspen
 *
 * This is a formally-verified implementation of BLAKE2 produced by HACL*.
 */

#include <crypto/blake2b.h>
#include <crypto/blake2s.h>
#include <crypto/internal/blake2b.h>

#include "hacl_hash.h"
#include "hacl_lib.h"

int hacl_blake2b_init(struct shash_desc *desc)
{
        unsigned int outlen = crypto_shash_digestsize(desc->tfm);
        struct Hacl_Streaming_Blake2_blake2b_32_state_s *state =
                shash_desc_ctx(desc);
        uint8_t *buf = (uint8_t *)kmalloc((uint32_t)128U, sizeof(uint8_t));
        uint64_t *wv = (uint64_t *)kmalloc((uint32_t)16U, sizeof(uint64_t));
        uint64_t *b = (uint64_t *)kmalloc((uint32_t)16U, sizeof(uint64_t));
        struct Hacl_Streaming_Blake2_blake2b_32_block_state_s block_state = {
                .fst = wv, .snd = b
        };
        struct Hacl_Streaming_Blake2_blake2b_32_state_s s1 = {
                .block_state = block_state,
                .buf = buf,
                .total_len = (uint64_t)(uint32_t)0U
        };
        state[0] = s1;
        Hacl_Blake2b_32_blake2b_init(block_state.snd, (uint32_t)0U,
                                     (uint32_t)outlen);
        return 0;
}
EXPORT_SYMBOL(hacl_blake2b_init);

int hacl_blake2b_update(struct shash_desc *desc, const u8 *in,
                        unsigned int inlen)
{
        struct Hacl_Streaming_Blake2_blake2b_32_state_s *sctx =
                shash_desc_ctx(desc);
        Hacl_Streaming_Blake2_blake2b_32_no_key_update(sctx, (u8 *)in, inlen);
        return 0;
}
EXPORT_SYMBOL(hacl_blake2b_update);

int hacl_blake2b_final(struct shash_desc *desc, u8 *out)
{
        struct Hacl_Streaming_Blake2_blake2b_32_state_s *sctx =
                shash_desc_ctx(desc);
        Hacl_Streaming_Blake2_blake2b_32_no_key_finish(sctx, out);
        struct Hacl_Streaming_Blake2_blake2b_32_state_s scrut = *sctx;
        uint8_t *buf = scrut.buf;
        struct Hacl_Streaming_Blake2_blake2b_32_block_state_s block_state =
                scrut.block_state;
        uint64_t *wv = block_state.fst;
        uint64_t *b = block_state.snd;
        kfree(wv);
        kfree(b);
        kfree(buf);
        return 0;
}
EXPORT_SYMBOL(hacl_blake2b_final);

#define BLAKE2B_ALG(name, driver_name, digest_size)                         \
        {                                                                   \
                .base.cra_name = name, .base.cra_driver_name = driver_name, \
                .base.cra_priority = 100,                                   \
                .base.cra_blocksize = BLAKE2B_BLOCK_SIZE,                   \
                .base.cra_module = THIS_MODULE, .digestsize = digest_size,  \
                .init = hacl_blake2b_init, .update = hacl_blake2b_update,   \
                .final = hacl_blake2b_final,                                \
                .descsize = sizeof(                                         \
                        struct Hacl_Streaming_Blake2_blake2b_32_state_s),   \
        }

int hacl_blake2s_init(struct shash_desc *desc)
{
        unsigned int outlen = crypto_shash_digestsize(desc->tfm);
        struct Hacl_Streaming_Blake2_blake2s_32_state_s *state =
                shash_desc_ctx(desc);
        uint8_t *buf = (uint8_t *)kmalloc((uint32_t)64U, sizeof(uint8_t));
        uint32_t *wv = (uint32_t *)kmalloc((uint32_t)16U, sizeof(uint32_t));
        uint32_t *b = (uint32_t *)kmalloc((uint32_t)16U, sizeof(uint32_t));
        struct Hacl_Streaming_Blake2_blake2s_32_block_state_s block_state = {
                .fst = wv, .snd = b
        };
        struct Hacl_Streaming_Blake2_blake2s_32_state_s s1 = {
                .block_state = block_state,
                .buf = buf,
                .total_len = (uint64_t)(uint32_t)0U
        };
        state[0] = s1;
        Hacl_Blake2s_32_blake2s_init(block_state.snd, (uint32_t)0U,
                                     (uint32_t)outlen);
        return 0;
}
EXPORT_SYMBOL(hacl_blake2s_init);

int hacl_blake2s_update(struct shash_desc *desc, const u8 *in,
                        unsigned int inlen)
{
        struct Hacl_Streaming_Blake2_blake2s_32_state_s *sctx =
                shash_desc_ctx(desc);
        Hacl_Streaming_Blake2_blake2s_32_no_key_update(sctx, (u8 *)in, inlen);
        return 0;
}
EXPORT_SYMBOL(hacl_blake2s_update);

int hacl_blake2s_final(struct shash_desc *desc, u8 *out)
{
        struct Hacl_Streaming_Blake2_blake2s_32_state_s *sctx =
                shash_desc_ctx(desc);
        Hacl_Streaming_Blake2_blake2s_32_no_key_finish(sctx, out);
        struct Hacl_Streaming_Blake2_blake2s_32_state_s scrut = *sctx;
        uint8_t *buf = scrut.buf;
        struct Hacl_Streaming_Blake2_blake2s_32_block_state_s block_state =
                scrut.block_state;
        uint32_t *wv = block_state.fst;
        uint32_t *b = block_state.snd;
        kfree(wv);
        kfree(b);
        kfree(buf);
        return 0;
}
EXPORT_SYMBOL(hacl_blake2s_final);

#define BLAKE2S_ALG(name, driver_name, digest_size)                         \
        {                                                                   \
                .base.cra_name = name, .base.cra_driver_name = driver_name, \
                .base.cra_priority = 100,                                   \
                .base.cra_blocksize = BLAKE2S_BLOCK_SIZE,                   \
                .base.cra_module = THIS_MODULE, .digestsize = digest_size,  \
                .init = hacl_blake2s_init, .update = hacl_blake2s_update,   \
                .final = hacl_blake2s_final,                                \
                .descsize = sizeof(                                         \
                        struct Hacl_Streaming_Blake2_blake2s_32_state_s),   \
        }

static struct shash_alg blake2_hacl_algs[] = {
        BLAKE2B_ALG("blake2b-160", "blake2b-160-hacl", BLAKE2B_160_HASH_SIZE),
        BLAKE2B_ALG("blake2b-256", "blake2b-256-hacl", BLAKE2B_256_HASH_SIZE),
        BLAKE2B_ALG("blake2b-384", "blake2b-384-hacl", BLAKE2B_384_HASH_SIZE),
        BLAKE2B_ALG("blake2b-512", "blake2b-512-hacl", BLAKE2B_512_HASH_SIZE),
        BLAKE2S_ALG("blake2s-160", "blake2s-160-hacl", 20),
        BLAKE2S_ALG("blake2s-256", "blake2s-256-hacl", 32),
};

static int __init blake2_hacl_mod_init(void)
{
        return crypto_register_shashes(blake2_hacl_algs,
                                       ARRAY_SIZE(blake2_hacl_algs));
}

static void __exit blake2_hacl_mod_fini(void)
{
        crypto_unregister_shashes(blake2_hacl_algs,
                                  ARRAY_SIZE(blake2_hacl_algs));
}

subsys_initcall(blake2_hacl_mod_init);
module_exit(blake2_hacl_mod_fini);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Formally Verified BLAKE2 Secure Hash Algorithm from HACL*");

MODULE_ALIAS_CRYPTO("blake2b-160");
MODULE_ALIAS_CRYPTO("blake2b-160-hacl");
MODULE_ALIAS_CRYPTO("blake2b-256");
MODULE_ALIAS_CRYPTO("blake2b-256-hacl");
MODULE_ALIAS_CRYPTO("blake2b-384");
MODULE_ALIAS_CRYPTO("blake2b-384-hacl");
MODULE_ALIAS_CRYPTO("blake2b-512");
MODULE_ALIAS_CRYPTO("blake2b-512-hacl");
MODULE_ALIAS_CRYPTO("blake2s-160");
MODULE_ALIAS_CRYPTO("blake2s-160-hacl");
MODULE_ALIAS_CRYPTO("blake2s-256");
MODULE_ALIAS_CRYPTO("blake2s-256-hacl");
