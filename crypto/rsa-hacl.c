/*
 * GPLv2 or MIT License
 *
 * Copyright (c) 2023 Cryspen
 *
 */

#include "hacl_rsa.h"

#include <linux/fips.h>
#include <linux/module.h>
#include <linux/mpi.h>
#include <crypto/internal/rsa.h>
#include <crypto/internal/akcipher.h>
#include <crypto/akcipher.h>
#include <crypto/algapi.h>

/**
RSA Key data structure
**/

struct hacl_rsa_key {
    uint32_t modBits;
    uint32_t eBits;
    uint32_t dBits;
    uint8_t* nbytes;
    uint8_t* ebytes;
    uint8_t* dbytes;
};

static inline struct hacl_rsa_key *rsa_get_key(struct crypto_akcipher *tfm)
{
	return akcipher_tfm_ctx(tfm);
}

static int rsa_enc(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	const struct hacl_rsa_key *pkey = rsa_get_key(tfm);
	int ret = 0;

	if (unlikely(!pkey->nbytes || !pkey->ebytes)) {
		ret = -EINVAL;
		goto done;
	}

	uint64_t* pk = Hacl_RSA_new_rsa_load_pkey(pkey->modBits,pkey->eBits,pkey->nbytes,pkey->ebytes);

	if (!pk) {
		ret = -EINVAL;
		goto done;
	}

	
	unsigned int plain_len = (pkey->modBits - 1)/8 + 1;
	unsigned int cipher_len = (pkey->modBits - 2)/8 + 1;

	if (req->src_len > plain_len || req->dst_len != cipher_len) {
		ret = -EINVAL;
		goto pkdone;
	}
	unsigned char* buffer = kzalloc(plain_len+cipher_len, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto pkdone;
	}
	sg_copy_to_buffer(req->src,
		          sg_nents_for_len(req->src, req->src_len),
			  buffer+plain_len-req->src_len, req->src_len);
	
	ret = Hacl_RSA_rsa_enc(pkey->modBits,pkey->eBits,pk,buffer,buffer+plain_len);

	if (!ret) {
		ret = -EBADMSG;
   	        goto bufdone;
	}

	sg_copy_from_buffer(req->dst,
		          sg_nents_for_len(req->dst, req->dst_len),
			  buffer+plain_len, cipher_len);

	
 bufdone: kfree(buffer);
 pkdone: kfree(pk);
 done:  return !ret;
}

static int rsa_dec(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	const struct hacl_rsa_key *skey = rsa_get_key(tfm);
	int ret = 0;

	if (unlikely(!skey->nbytes || !skey->dbytes || !skey->ebytes)) {
		ret = -EINVAL;
		goto done;
	}

	uint64_t *sk = Hacl_RSA_new_rsa_load_skey(skey->modBits,skey->eBits,skey->dBits,skey->nbytes,skey->ebytes,skey->dbytes);

	if (!sk) {
		ret = -EINVAL;
		goto done;
	}

	
	unsigned int plain_len = (skey->modBits - 1)/8 + 1;
	unsigned int cipher_len = (skey->modBits - 2)/8 + 1;

	if (req->src_len > cipher_len || req->dst_len != plain_len) {
		ret = -EINVAL;
		goto skdone;
	}

	unsigned char* buffer = kzalloc(plain_len + cipher_len, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto skdone;
	}
	
	sg_copy_to_buffer(req->src,
		          sg_nents_for_len(req->src, req->src_len),
			  buffer+cipher_len-req->src_len, req->src_len);
	
	ret = Hacl_RSA_rsa_dec(skey->modBits,skey->eBits,skey->dBits,sk,buffer,buffer+cipher_len);

	if (!ret) {
		ret = -EBADMSG;
		goto bufdone;
	}
	
	sg_copy_from_buffer(req->dst,
		          sg_nents_for_len(req->dst, req->dst_len),
			  buffer+cipher_len, req->dst_len);

bufdone: kfree(buffer);
 skdone: kfree(sk);
 done:	 return !ret;
}

static void rsa_free_key(struct hacl_rsa_key *key)
{
        if (key->nbytes != NULL) kfree(key->nbytes);
        if (key->ebytes != NULL) kfree(key->ebytes);
        if (key->dbytes != NULL) kfree(key->dbytes);
	key->modBits = 0;
	key->eBits = 0;
	key->dBits = 0;
	key->nbytes = NULL;
	key->ebytes = NULL;
	key->dbytes = NULL;
}

static int rsa_set_pub_key(struct crypto_akcipher *tfm, const void *key,
			   unsigned int keylen)
{
	struct hacl_rsa_key *pkey = rsa_get_key(tfm);
	struct rsa_key raw_key = {0};
	
	int ret = 0;

	/* Free the old MPI key if any */
	rsa_free_key(pkey);

	ret = rsa_parse_pub_key(&raw_key, key, keylen);
	if (ret)
		return ret;

	int n_sz = raw_key.n_sz;
	if (raw_key.n[0] == 0) {
	  n_sz -= 1;
	}
	pkey->modBits = n_sz * 8;
	pkey->eBits = raw_key.e_sz * 8;
	if (pkey->eBits == 24 && raw_key.e[0] == 1) pkey->eBits = 17;
	pkey->dBits = 0;

	pkey->nbytes = kzalloc(n_sz, GFP_KERNEL);
	if (!pkey->nbytes)
	        goto err;
	memcpy(pkey->nbytes,raw_key.n+raw_key.n_sz-n_sz,n_sz);
	
	pkey->ebytes = kzalloc(raw_key.e_sz, GFP_KERNEL);
	if (!pkey->ebytes)
	        goto err;
	memcpy(pkey->ebytes,raw_key.e,raw_key.e_sz);

	pkey->dbytes = NULL;
	return ret;
	
err:
	rsa_free_key(pkey);
	return -ENOMEM;
}

static int rsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
			   unsigned int keylen)
{
	struct hacl_rsa_key *skey = rsa_get_key(tfm);
	struct rsa_key raw_key = {0};
	
	int ret = 0;

	/* Free the old MPI key if any */
	rsa_free_key(skey);

	ret = rsa_parse_priv_key(&raw_key, key, keylen);
	if (ret)
		return ret;

	int n_sz = raw_key.n_sz;
	if (raw_key.n[0] == 0) {
	  n_sz -= 1;
	}
	skey->modBits = n_sz * 8;
	skey->eBits = raw_key.e_sz * 8;
	if (skey->eBits == 24 && raw_key.e[0] == 1) skey->eBits = 17;
	skey->dBits = raw_key.d_sz * 8;

	skey->nbytes = kzalloc(n_sz, GFP_KERNEL);
	if (!skey->nbytes)
	        goto err;
	memcpy(skey->nbytes,raw_key.n+raw_key.n_sz-n_sz,n_sz);
	
	skey->ebytes = kzalloc(raw_key.e_sz, GFP_KERNEL);
	if (!skey->ebytes)
	        goto err;
	memcpy(skey->ebytes,raw_key.e,raw_key.e_sz);

	skey->dbytes = kzalloc(raw_key.d_sz, GFP_KERNEL);
	if (!skey->dbytes)
	        goto err;
	memcpy(skey->dbytes,raw_key.d,raw_key.d_sz);
	
	return ret;
	
err:
	rsa_free_key(skey);
	return -ENOMEM;
}

static unsigned int rsa_max_size(struct crypto_akcipher *tfm)
{
	struct hacl_rsa_key *key = akcipher_tfm_ctx(tfm);
	return ((key->modBits-1)/8)+1;
}

static void rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct hacl_rsa_key *key = akcipher_tfm_ctx(tfm);
	rsa_free_key(key);
}

static struct akcipher_alg hacl_rsa = {
	.encrypt = rsa_enc,
	.decrypt = rsa_dec,
	.set_priv_key = rsa_set_priv_key,
	.set_pub_key = rsa_set_pub_key,
	.max_size = rsa_max_size,
	.exit = rsa_exit_tfm,
	.base = {
		.cra_name = "rsa",
		.cra_driver_name = "rsa-hacl",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct hacl_rsa_key),
	},
};

static int __init hacl_rsa_init(void)
{
	int err;

	err = crypto_register_akcipher(&hacl_rsa);
	if (err)
		return err;

	err = crypto_register_template(&rsa_pkcs1pad_tmpl);
	if (err) {
		crypto_unregister_akcipher(&hacl_rsa);
		return err;
	}

	return 0;
}

static void __exit hacl_rsa_exit(void)
{
	crypto_unregister_template(&rsa_pkcs1pad_tmpl);
	crypto_unregister_akcipher(&hacl_rsa);
}

subsys_initcall(hacl_rsa_init);
module_exit(hacl_rsa_exit);
MODULE_ALIAS_CRYPTO("rsa");
MODULE_ALIAS_CRYPTO("rsa-hacl");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Formally Verified RSA algorithm from HACL*");
