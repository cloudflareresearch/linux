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
    uint8_t *nb;
    uint8_t *eb;
    uint8_t *db;
};

static inline struct hacl_rsa_key *rsa_get_key(struct crypto_akcipher *tfm)
{
	return akcipher_tfm_ctx(tfm);
}

static int rsa_enc(struct akcipher_request *req)
{
  //  printk("<<< in rsa enc");
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	const struct hacl_rsa_key *pkey = rsa_get_key(tfm);
	int ret = 0;
	//  printk("<<< in hacl rsa_enc");
	//  printk("<<<<<<<<<<<<<<<<<<<<<<<<<<< pkey->modbits:%d, pkey->ebits:%d, pkey->dbits:%d", pkey->modBits,pkey->eBits,pkey->dBits);

	if (unlikely(!pkey->nb || !pkey->eb)) {
		ret = -EINVAL;
		goto done;
	}
	unsigned int plain_len = (pkey->modBits - 1)/8 + 1;
	unsigned int cipher_len = (pkey->modBits - 2)/8 + 1;

	//  printk("req->src_len:%d, plain_len:%d, req->dst_len:%d, cipher_len:%d", req->src_len,plain_len,req->dst_len,cipher_len);
	if (req->src_len > plain_len || req->dst_len != cipher_len) {
		ret = -EINVAL;
		goto done;
	}
	unsigned char* pbuffer = kzalloc(plain_len, GFP_KERNEL);
	unsigned char* cbuffer = kzalloc(cipher_len, GFP_KERNEL);
	if (!pbuffer || !cbuffer)
		return -ENOMEM;
	sg_copy_to_buffer(req->src,
		          sg_nents_for_len(req->src, req->src_len),
			  pbuffer+plain_len-req->src_len, req->src_len);
	
	uint64_t *pk = Hacl_RSA_new_rsa_load_pkey(pkey->modBits,pkey->eBits,pkey->nb,pkey->eb);

	if (!pk) {
	        printk("<<< load pkey failed");
		ret = -EINVAL;
		goto done;
	}
	//	printk("<<< loaded pkey with modbits = %d, nb[0] = %x, nb[63] = %x, ebits = %d, eb[0] = %x", pkey->modBits, pkey->nb[0], pkey->nb[63], pkey->eBits, pkey->eb[0]);
	//	printk("<<< calling HACL_RSA_rsa_enc with msg[plain_len-1] = %x, msg[..] = %x",pbuffer[plain_len-1],pbuffer[plain_len - req->src_len]);
	
	ret = Hacl_RSA_rsa_enc(pkey->modBits,pkey->eBits, pk, pbuffer, cbuffer);


	if (!ret)
	         ret = -EBADMSG;

	//	printk("<<< exiting hacl rsa_enc 5 with cipher_len=%d, dst_len=%d, nents=%d, cipher[0]=%x, cipher[15]=%x",
	//	       cipher_len,req->dst_len,sg_nents_for_len(req->dst, req->dst_len),cbuffer[0],cbuffer[15]);
	int copied = sg_copy_from_buffer(req->dst,
		          sg_nents_for_len(req->dst, req->dst_len),
			  cbuffer, cipher_len);
	(void)copied;
	//printk("<<< exiting hacl rsa_enc 6 with copied = %d, cipher_len=%d, cipher[0]=%x, cipher[15]=%x",
	//       copied, cipher_len,cbuffer[0],cbuffer[15]);
	kfree(pk);

 done:  kfree(pbuffer);
	kfree(cbuffer);
	return !ret;
}

static int rsa_dec(struct akcipher_request *req)
{
  //  printk("<<< in rsa dec");
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	const struct hacl_rsa_key *skey = rsa_get_key(tfm);
	int ret = 0;

	if (unlikely(!skey->nb || !skey->db)) {
		ret = -EINVAL;
		goto done;
	}
	unsigned int plain_len = (skey->modBits - 1)/8 + 1;
	unsigned int cipher_len = (skey->modBits - 2)/8 + 1;
	//  printk("<<<<< pkey->modbits:%d, pkey->ebits:%d, pkey->dbits:%d", skey->modBits,skey->eBits,skey->dBits);
	//  printk("<<<<< req->src_len:%d, plain_len:%d, req->dst_len:%d, cipher_len:%d", req->src_len,plain_len,req->dst_len,cipher_len);

	if (req->src_len > cipher_len || req->dst_len != plain_len) {
	  printk("not the right lengths");
		ret = -EINVAL;
		goto done;
	}

	unsigned char* buffer = kzalloc(plain_len + cipher_len, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	sg_copy_to_buffer(req->src,
		          sg_nents_for_len(req->src, req->src_len),
			  buffer+cipher_len-req->src_len, req->src_len);
	
	uint64_t *sk = Hacl_RSA_new_rsa_load_skey(skey->modBits,skey->eBits,skey->dBits,skey->nb,skey->eb,skey->db);

	if (!sk) {
	        printk("<<< load skey failed");
		ret = -EINVAL;
		goto done;
	}
	
	ret = Hacl_RSA_rsa_dec(skey->modBits,skey->eBits,skey->dBits,sk,buffer,buffer+cipher_len);

	if (!ret) {
	        printk("<<< rsa_dec failed");
	         ret = -EBADMSG;
	}
	
	//	printk("<<< exiting hacl rsa_dec 5 with plain_len=%d, dst_len=%d, nents=%d, plain[0]=%x, plain[15]=%x",
	//	       plain_len,req->dst_len,sg_nents_for_len(req->dst, req->dst_len),buffer[cipher_len],buffer[cipher_len+15]);
	sg_copy_from_buffer(req->dst,
		          sg_nents_for_len(req->dst, req->dst_len),
			  buffer+cipher_len, req->dst_len);

	kfree(sk);

 done:  kfree(buffer);
	return !ret;
}

static void rsa_free_key(struct hacl_rsa_key *key)
{
        if (key->db != NULL) kfree(key->db);
	if (key->eb != NULL) kfree(key->eb);
	if (key->nb != NULL) kfree(key->nb);
	key->modBits = 0;
	key->eBits = 0;
	key->dBits = 0;
	key->db = NULL;
	key->eb = NULL;
	key->nb = NULL;
}

static int rsa_set_pub_key(struct crypto_akcipher *tfm, const void *key,
			   unsigned int keylen)
{
  //  printk("<<< calling hacl rsa_set_pub_key");

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
	
	/* THIS IS JUST TO AVOID STACK OVERFLOW FOR NOW */
	if (n_sz > 256)
	  goto err;
	
	pkey->modBits = n_sz * 8;

	pkey->nb = kzalloc(n_sz,GFP_KERNEL);
	if (!pkey->nb)
		goto err;	
	memcpy(pkey->nb,raw_key.n+raw_key.n_sz-n_sz,n_sz);
	
	pkey->eBits = raw_key.e_sz * 8;
	pkey->eb = kzalloc(raw_key.e_sz,GFP_KERNEL);
	if (!pkey->eb)
		goto err;
	memcpy(pkey->eb,raw_key.e,raw_key.e_sz);

	return ret;
	
err:
	rsa_free_key(pkey);
	return -ENOMEM;
}

static int rsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
			   unsigned int keylen)
{
  //    printk("<<< calling hacl rsa_set_priv_key");
  
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

	/* THIS IS JUST TO AVOID STACK OVERFLOW FOR NOW */
	if (n_sz > 256)
	  goto err;

	skey->modBits = n_sz * 8;

	skey->nb = kzalloc(n_sz,GFP_KERNEL);
	if (!skey->nb)
		goto err;	
	memcpy(skey->nb,raw_key.n+raw_key.n_sz-n_sz,n_sz);
	
	skey->eBits = raw_key.e_sz * 8;
	skey->eb = kzalloc(raw_key.e_sz,GFP_KERNEL);
	if (!skey->eb)
		goto err;
	memcpy(skey->eb,raw_key.e,raw_key.e_sz);

	skey->dBits = raw_key.d_sz * 8;
	skey->db = kzalloc(raw_key.d_sz,GFP_KERNEL);
	if (!skey->db)
		goto err;
	memcpy(skey->db,raw_key.d,raw_key.d_sz);

	//    printk("<<< leaving hacl rsa_set_priv_key");
	return ret;
	
err:
	rsa_free_key(skey);
	return -ENOMEM;
}

static unsigned int rsa_max_size(struct crypto_akcipher *tfm)
{
	struct hacl_rsa_key *pkey = akcipher_tfm_ctx(tfm);
	return ((pkey->modBits-1)/8)+1;
}

static void rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct hacl_rsa_key *pkey = akcipher_tfm_ctx(tfm);

	rsa_free_key(pkey);
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
