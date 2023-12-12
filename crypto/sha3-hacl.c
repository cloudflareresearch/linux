// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (c) 2023 Cryspen
 *
 * This is a formally-verified implementation of SHA-3 produced by HACL*.
 */

#include <crypto/sha3.h>

#include "hacl_hash.h"
#include "hacl_lib.h"

int hacl_sha3_init(struct shash_desc *desc)
{
        struct sha3_state *sctx = shash_desc_ctx(desc);
        unsigned int digest_size = crypto_shash_digestsize(desc->tfm);
        sctx->rsiz = 200 - 2 * digest_size;
        sctx->rsizw = sctx->rsiz / 8;
        sctx->partial = 0;
        memset(sctx->st, 0, sizeof(sctx->st));
        return 0;
}
EXPORT_SYMBOL(hacl_sha3_init);

Spec_Hash_Definitions_hash_alg hacl_sha3_alg(unsigned int rsiz)
{
        switch (rsiz) {
        case 144: {
                return Spec_Hash_Definitions_SHA3_224;
        }
        case 136: {
                return Spec_Hash_Definitions_SHA3_256;
        }
        case 104: {
                return Spec_Hash_Definitions_SHA3_384;
        }
        case 72: {
                return Spec_Hash_Definitions_SHA3_512;
        }
        default: {
                return Spec_Hash_Definitions_SHA3_256;
        }
        }
}

int hacl_sha3_update(struct shash_desc *desc, const u8 *data, unsigned int len)
{
        struct sha3_state *sctx = shash_desc_ctx(desc);
        struct Hacl_Streaming_Keccak_state_s st;
        st.block_state.fst = hacl_sha3_alg(sctx->rsiz);
        st.block_state.snd = sctx->st;
        st.buf = sctx->buf;
        st.total_len = 0;
        uint8_t ret = Hacl_Streaming_Keccak_update(&st, (uint8_t *)data, len);
        if (ret > 0) {
                return -1;
        } else {
                return 0;
        }
}
EXPORT_SYMBOL(hacl_sha3_update);

int hacl_sha3_final(struct shash_desc *desc, u8 *out)
{
        struct sha3_state *sctx = shash_desc_ctx(desc);
        struct Hacl_Streaming_Keccak_state_s st;
        st.block_state.fst = hacl_sha3_alg(sctx->rsiz);
        st.block_state.snd = sctx->st;
        st.buf = sctx->buf;
        st.total_len = 0;
        uint8_t ret = Hacl_Streaming_Keccak_finish(&st, out);
        if (ret > 0) {
                return -1;
        } else {
                return 0;
        }
}
EXPORT_SYMBOL(hacl_sha3_final);

static struct shash_alg algs[] = {
        {
                .digestsize = SHA3_224_DIGEST_SIZE,
                .init = hacl_sha3_init,
                .update = hacl_sha3_update,
                .final = hacl_sha3_final,
                .descsize = sizeof(struct sha3_state),
                .base.cra_name = "sha3-224",
                .base.cra_driver_name = "sha3-224-hacl",
                .base.cra_blocksize = SHA3_224_BLOCK_SIZE,
                .base.cra_module = THIS_MODULE,
        },
        {
                .digestsize = SHA3_256_DIGEST_SIZE,
                .init = hacl_sha3_init,
                .update = hacl_sha3_update,
                .final = hacl_sha3_final,
                .descsize = sizeof(struct sha3_state),
                .base.cra_name = "sha3-256",
                .base.cra_driver_name = "sha3-256-hacl",
                .base.cra_blocksize = SHA3_256_BLOCK_SIZE,
                .base.cra_module = THIS_MODULE,
        },
        {
                .digestsize = SHA3_384_DIGEST_SIZE,
                .init = hacl_sha3_init,
                .update = hacl_sha3_update,
                .final = hacl_sha3_final,
                .descsize = sizeof(struct sha3_state),
                .base.cra_name = "sha3-384",
                .base.cra_driver_name = "sha3-384-hacl",
                .base.cra_blocksize = SHA3_384_BLOCK_SIZE,
                .base.cra_module = THIS_MODULE,
        },
        {
                .digestsize = SHA3_512_DIGEST_SIZE,
                .init = hacl_sha3_init,
                .update = hacl_sha3_update,
                .final = hacl_sha3_final,
                .descsize = sizeof(struct sha3_state),
                .base.cra_name = "sha3-512",
                .base.cra_driver_name = "sha3-512-hacl",
                .base.cra_blocksize = SHA3_512_BLOCK_SIZE,
                .base.cra_module = THIS_MODULE,
        }
};

static int test_hash(char *hash_alg_name, const unsigned char *data,
                     unsigned int datalen, unsigned char *digest,
                     unsigned int digestlen)
{
        struct crypto_shash *alg;
        struct shash_desc *sdesc;
        char out[300];
        int size;
        int ret;
        alg = crypto_alloc_shash(hash_alg_name, 0, CRYPTO_ALG_ASYNC);
        if (IS_ERR(alg)) {
                pr_info("can't alloc alg %s\n", hash_alg_name);
                return PTR_ERR(alg);
        }
        size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
        sdesc = kmalloc(size, GFP_KERNEL);
        if (IS_ERR(sdesc)) {
                pr_info("can't alloc sdesc\n");
                return PTR_ERR(sdesc);
        }
        sdesc->tfm = alg;
        hacl_sha3_init(sdesc);
        hacl_sha3_update(sdesc, data, datalen);
        hacl_sha3_final(sdesc, digest);
        pr_err("Name: %s\n", hash_alg_name);
        memset(out, 0, ARRAY_SIZE(out));
        for (int i = 0; i < digestlen; i++)
                snprintf(out, ARRAY_SIZE(out), "%s%02x", out, digest[i]);
        pr_err("hacl:    %s\n", out);
        ret = crypto_shash_digest(sdesc, data, datalen, digest);
        memset(out, 0, ARRAY_SIZE(out));
        for (int i = 0; i < digestlen; i++)
                snprintf(out, ARRAY_SIZE(out), "%s%02x", out, digest[i]);
        pr_err("generic: %s\n", out);
        kfree(sdesc);
        crypto_free_shash(alg);
        return ret;
}

static int __init sha3_hacl_mod_init(void)
{
        unsigned char data[1];
        unsigned char out[SHA3_512_DIGEST_SIZE];
        data[0] = 'a';
        int datalen = ARRAY_SIZE(data);
        test_hash("sha3-224", data, datalen, out, SHA3_224_DIGEST_SIZE);
        test_hash("sha3-256", data, datalen, out, SHA3_256_DIGEST_SIZE);
        test_hash("sha3-384", data, datalen, out, SHA3_384_DIGEST_SIZE);
        test_hash("sha3-512", data, datalen, out, SHA3_512_DIGEST_SIZE);
        return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}

static void __exit sha3_hacl_mod_fini(void)
{
        crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

subsys_initcall(sha3_hacl_mod_init);
module_exit(sha3_hacl_mod_fini);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Formally Verified SHA-3 Secure Hash Algorithm from HACL*");

MODULE_ALIAS_CRYPTO("sha3-224");
MODULE_ALIAS_CRYPTO("sha3-224-hacl");
MODULE_ALIAS_CRYPTO("sha3-256");
MODULE_ALIAS_CRYPTO("sha3-256-hacl");
MODULE_ALIAS_CRYPTO("sha3-384");
MODULE_ALIAS_CRYPTO("sha3-384-hacl");
MODULE_ALIAS_CRYPTO("sha3-512");
MODULE_ALIAS_CRYPTO("sha3-512-hacl");
