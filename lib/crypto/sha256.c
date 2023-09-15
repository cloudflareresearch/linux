// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SHA-256, as specified in
 * http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
 *
 * SHA-256 code by Jean-Luc Cooke <jlcooke@certainkey.com>.
 *
 * Copyright (c) Jean-Luc Cooke <jlcooke@certainkey.com>
 * Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2014 Red Hat Inc.
 */

#include "hacl_hash.h"
#include "hacl_sha2.h"

void sha256_update(struct sha256_state *sctx, const u8 *data, unsigned int len)
{
  Hacl_Streaming_MD_state_32 st;
  st.block_state = sctx->state;
  st.buf = sctx->buf;
  st.total_len = sctx->count;
  Hacl_Streaming_SHA2_update_256(&st, (u8*)data, len);
  sctx->count = st.total_len;
}
EXPORT_SYMBOL(sha256_update);

void sha256_final(struct sha256_state *sctx, u8 *out)
{
  Hacl_Streaming_MD_state_32 st;
  st.block_state = sctx->state;
  st.buf = sctx->buf;
  st.total_len = sctx->count;
  Hacl_Streaming_SHA2_finish_256(&st,out);
}
EXPORT_SYMBOL(sha256_final);

void sha224_final(struct sha256_state *sctx, u8 *out)
{
  Hacl_Streaming_MD_state_32 st;
  st.block_state = sctx->state;
  st.buf = sctx->buf;
  st.total_len = sctx->count;
  Hacl_Streaming_SHA2_finish_224(&st,out);
}
EXPORT_SYMBOL(sha224_final);

void sha256(const u8 *data, unsigned int len, u8 *out)
{
	struct sha256_state sctx;

	sha256_init(&sctx);
	sha256_update(&sctx, data, len);
	sha256_final(&sctx, out);
}
EXPORT_SYMBOL(sha256);

MODULE_LICENSE("GPL");
