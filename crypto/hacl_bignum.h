/*
 * Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation
 * Copyright (c) 2022-2023 HACL* Contributors
 * Copyright (c) 2023 Cryspen
 */

#ifndef CRYPTO_HACL_BIGNUM_H_
#define CRYPTO_HACL_BIGNUM_H_

#include "hacl_lib.h"
#include "bignum-hacl-base-generated.h"

typedef struct Hacl_Bignum_MontArithmetic_bn_mont_ctx_u32_s
{
  uint32_t len;
  uint32_t *n;
  uint32_t mu;
  uint32_t *r2;
}
Hacl_Bignum_MontArithmetic_bn_mont_ctx_u32;

typedef struct Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64_s
{
  uint32_t len;
  uint64_t *n;
  uint64_t mu;
  uint64_t *r2;
}
Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64;


void
Hacl_Bignum_Karatsuba_bn_karatsuba_mul_uint32(
  uint32_t aLen,
  uint32_t *a,
  uint32_t *b,
  uint32_t *tmp,
  uint32_t *res
);

void
Hacl_Bignum_Karatsuba_bn_karatsuba_mul_uint64(
  uint32_t aLen,
  uint64_t *a,
  uint64_t *b,
  uint64_t *tmp,
  uint64_t *res
);

void
Hacl_Bignum_Karatsuba_bn_karatsuba_sqr_uint32(
  uint32_t aLen,
  uint32_t *a,
  uint32_t *tmp,
  uint32_t *res
);

void
Hacl_Bignum_Karatsuba_bn_karatsuba_sqr_uint64(
  uint32_t aLen,
  uint64_t *a,
  uint64_t *tmp,
  uint64_t *res
);

void
Hacl_Bignum_bn_add_mod_n_u32(
  uint32_t len1,
  uint32_t *n,
  uint32_t *a,
  uint32_t *b,
  uint32_t *res
);

void
Hacl_Bignum_bn_add_mod_n_u64(
  uint32_t len1,
  uint64_t *n,
  uint64_t *a,
  uint64_t *b,
  uint64_t *res
);

void
Hacl_Bignum_bn_sub_mod_n_u32(
  uint32_t len1,
  uint32_t *n,
  uint32_t *a,
  uint32_t *b,
  uint32_t *res
);

void
Hacl_Bignum_bn_sub_mod_n_u64(
  uint32_t len1,
  uint64_t *n,
  uint64_t *a,
  uint64_t *b,
  uint64_t *res
);

uint32_t Hacl_Bignum_ModInvLimb_mod_inv_uint32(uint32_t n0);

uint64_t Hacl_Bignum_ModInvLimb_mod_inv_uint64(uint64_t n0);

uint32_t Hacl_Bignum_Montgomery_bn_check_modulus_u32(uint32_t len, uint32_t *n);

void
Hacl_Bignum_Montgomery_bn_precomp_r2_mod_n_u32(
  uint32_t len,
  uint32_t nBits,
  uint32_t *n,
  uint32_t *res
);

void
Hacl_Bignum_Montgomery_bn_mont_reduction_u32(
  uint32_t len,
  uint32_t *n,
  uint32_t nInv,
  uint32_t *c,
  uint32_t *res
);

void
Hacl_Bignum_Montgomery_bn_to_mont_u32(
  uint32_t len,
  uint32_t *n,
  uint32_t nInv,
  uint32_t *r2,
  uint32_t *a,
  uint32_t *aM
);

void
Hacl_Bignum_Montgomery_bn_from_mont_u32(
  uint32_t len,
  uint32_t *n,
  uint32_t nInv_u64,
  uint32_t *aM,
  uint32_t *a
);

void
Hacl_Bignum_Montgomery_bn_mont_mul_u32(
  uint32_t len,
  uint32_t *n,
  uint32_t nInv_u64,
  uint32_t *aM,
  uint32_t *bM,
  uint32_t *resM
);

void
Hacl_Bignum_Montgomery_bn_mont_sqr_u32(
  uint32_t len,
  uint32_t *n,
  uint32_t nInv_u64,
  uint32_t *aM,
  uint32_t *resM
);

uint64_t Hacl_Bignum_Montgomery_bn_check_modulus_u64(uint32_t len, uint64_t *n);

void
Hacl_Bignum_Montgomery_bn_precomp_r2_mod_n_u64(
  uint32_t len,
  uint32_t nBits,
  uint64_t *n,
  uint64_t *res
);

void
Hacl_Bignum_Montgomery_bn_mont_reduction_u64(
  uint32_t len,
  uint64_t *n,
  uint64_t nInv,
  uint64_t *c,
  uint64_t *res
);

void
Hacl_Bignum_Montgomery_bn_to_mont_u64(
  uint32_t len,
  uint64_t *n,
  uint64_t nInv,
  uint64_t *r2,
  uint64_t *a,
  uint64_t *aM
);

void
Hacl_Bignum_Montgomery_bn_from_mont_u64(
  uint32_t len,
  uint64_t *n,
  uint64_t nInv_u64,
  uint64_t *aM,
  uint64_t *a
);

void
Hacl_Bignum_Montgomery_bn_mont_mul_u64(
  uint32_t len,
  uint64_t *n,
  uint64_t nInv_u64,
  uint64_t *aM,
  uint64_t *bM,
  uint64_t *resM
);

void
Hacl_Bignum_Montgomery_bn_mont_sqr_u64(
  uint32_t len,
  uint64_t *n,
  uint64_t nInv_u64,
  uint64_t *aM,
  uint64_t *resM
);

uint32_t
Hacl_Bignum_Exponentiation_bn_check_mod_exp_u32(
  uint32_t len,
  uint32_t *n,
  uint32_t *a,
  uint32_t bBits,
  uint32_t *b
);

void
Hacl_Bignum_Exponentiation_bn_mod_exp_vartime_precomp_u32(
  uint32_t len,
  uint32_t *n,
  uint32_t mu,
  uint32_t *r2,
  uint32_t *a,
  uint32_t bBits,
  uint32_t *b,
  uint32_t *res
);

void
Hacl_Bignum_Exponentiation_bn_mod_exp_consttime_precomp_u32(
  uint32_t len,
  uint32_t *n,
  uint32_t mu,
  uint32_t *r2,
  uint32_t *a,
  uint32_t bBits,
  uint32_t *b,
  uint32_t *res
);

void
Hacl_Bignum_Exponentiation_bn_mod_exp_vartime_u32(
  uint32_t len,
  uint32_t nBits,
  uint32_t *n,
  uint32_t *a,
  uint32_t bBits,
  uint32_t *b,
  uint32_t *res
);

void
Hacl_Bignum_Exponentiation_bn_mod_exp_consttime_u32(
  uint32_t len,
  uint32_t nBits,
  uint32_t *n,
  uint32_t *a,
  uint32_t bBits,
  uint32_t *b,
  uint32_t *res
);

uint64_t
Hacl_Bignum_Exponentiation_bn_check_mod_exp_u64(
  uint32_t len,
  uint64_t *n,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b
);

void
Hacl_Bignum_Exponentiation_bn_mod_exp_vartime_precomp_u64(
  uint32_t len,
  uint64_t *n,
  uint64_t mu,
  uint64_t *r2,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint64_t *res
);

void
Hacl_Bignum_Exponentiation_bn_mod_exp_consttime_precomp_u64(
  uint32_t len,
  uint64_t *n,
  uint64_t mu,
  uint64_t *r2,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint64_t *res
);

void
Hacl_Bignum_Exponentiation_bn_mod_exp_vartime_u64(
  uint32_t len,
  uint32_t nBits,
  uint64_t *n,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint64_t *res
);

void
Hacl_Bignum_Exponentiation_bn_mod_exp_consttime_u64(
  uint32_t len,
  uint32_t nBits,
  uint64_t *n,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint64_t *res
);


typedef Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *Hacl_Bignum64_pbn_mont_ctx_u64;

/*******************************************************************************

A verified bignum library.

This is a 64-bit optimized version, where bignums are represented as an array
of `len` unsigned 64-bit integers, i.e. uint64_t[len].

*******************************************************************************/

/************************/
/* Arithmetic functions */
/************************/


/**
Write `a + b mod 2 ^ (64 * len)` in `res`.

  This functions returns the carry.

  The arguments a, b and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len]
*/
uint64_t Hacl_Bignum64_add(uint32_t len, uint64_t *a, uint64_t *b, uint64_t *res);

/**
Write `a - b mod 2 ^ (64 * len)` in `res`.

  This functions returns the carry.

  The arguments a, b and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len]
*/
uint64_t Hacl_Bignum64_sub(uint32_t len, uint64_t *a, uint64_t *b, uint64_t *res);

/**
Write `(a + b) mod n` in `res`.

  The arguments a, b, n and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].

  Before calling this function, the caller will need to ensure that the following
  preconditions are observed.
  • a < n
  • b < n
*/
void Hacl_Bignum64_add_mod(uint32_t len, uint64_t *n, uint64_t *a, uint64_t *b, uint64_t *res);

/**
Write `(a - b) mod n` in `res`.

  The arguments a, b, n and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].

  Before calling this function, the caller will need to ensure that the following
  preconditions are observed.
  • a < n
  • b < n
*/
void Hacl_Bignum64_sub_mod(uint32_t len, uint64_t *n, uint64_t *a, uint64_t *b, uint64_t *res);

/**
Write `a * b` in `res`.

  The arguments a and b are meant to be `len` limbs in size, i.e. uint64_t[len].
  The outparam res is meant to be `2*len` limbs in size, i.e. uint64_t[2*len].
*/
void Hacl_Bignum64_mul(uint32_t len, uint64_t *a, uint64_t *b, uint64_t *res);

/**
Write `a * a` in `res`.

  The argument a is meant to be `len` limbs in size, i.e. uint64_t[len].
  The outparam res is meant to be `2*len` limbs in size, i.e. uint64_t[2*len].
*/
void Hacl_Bignum64_sqr(uint32_t len, uint64_t *a, uint64_t *res);

/**
Write `a mod n` in `res`.

  The argument a is meant to be `2*len` limbs in size, i.e. uint64_t[2*len].
  The argument n and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].

  The function returns false if any of the following preconditions are violated,
  true otherwise.
   • 1 < n
   • n % 2 = 1 
*/
bool Hacl_Bignum64_mod(uint32_t len, uint64_t *n, uint64_t *a, uint64_t *res);

/**
Write `a ^ b mod n` in `res`.

  The arguments a, n and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].

  The argument b is a bignum of any size, and bBits is an upper bound on the
  number of significant bits of b. A tighter bound results in faster execution
  time. When in doubt, the number of bits for the bignum size is always a safe
  default, e.g. if b is a 4096-bit bignum, bBits should be 4096.

  The function is *NOT* constant-time on the argument b. See the
  mod_exp_consttime_* functions for constant-time variants.

  The function returns false if any of the following preconditions are violated,
  true otherwise.
   • n % 2 = 1
   • 1 < n
   • b < pow2 bBits
   • a < n
*/
bool
Hacl_Bignum64_mod_exp_vartime(
  uint32_t len,
  uint64_t *n,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint64_t *res
);

/**
Write `a ^ b mod n` in `res`.

  The arguments a, n and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].

  The argument b is a bignum of any size, and bBits is an upper bound on the
  number of significant bits of b. A tighter bound results in faster execution
  time. When in doubt, the number of bits for the bignum size is always a safe
  default, e.g. if b is a 4096-bit bignum, bBits should be 4096.

  This function is constant-time over its argument b, at the cost of a slower
  execution time than mod_exp_vartime.

  The function returns false if any of the following preconditions are violated,
  true otherwise.
   • n % 2 = 1
   • 1 < n
   • b < pow2 bBits
   • a < n
*/
bool
Hacl_Bignum64_mod_exp_consttime(
  uint32_t len,
  uint64_t *n,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint64_t *res
);

/**
Write `a ^ (-1) mod n` in `res`.

  The arguments a, n and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].

  Before calling this function, the caller will need to ensure that the following
  preconditions are observed.
  • n is a prime

  The function returns false if any of the following preconditions are violated,
  true otherwise.
  • n % 2 = 1
  • 1 < n
  • 0 < a
  • a < n
*/
bool
Hacl_Bignum64_mod_inv_prime_vartime(uint32_t len, uint64_t *n, uint64_t *a, uint64_t *res);


/**********************************************/
/* Arithmetic functions with precomputations. */
/**********************************************/


/**
Heap-allocate and initialize a montgomery context.

  The argument n is meant to be `len` limbs in size, i.e. uint64_t[len].

  Before calling this function, the caller will need to ensure that the following
  preconditions are observed.
  • n % 2 = 1
  • 1 < n

  The caller will need to call Hacl_Bignum64_mont_ctx_free on the return value
  to avoid memory leaks.
*/
Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64
*Hacl_Bignum64_mont_ctx_init(uint32_t len, uint64_t *n);

/**
Deallocate the memory previously allocated by Hacl_Bignum64_mont_ctx_init.

  The argument k is a montgomery context obtained through Hacl_Bignum64_mont_ctx_init.
*/
void Hacl_Bignum64_mont_ctx_free(Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k);

/**
Write `a mod n` in `res`.

  The argument a is meant to be `2*len` limbs in size, i.e. uint64_t[2*len].
  The outparam res is meant to be `len` limbs in size, i.e. uint64_t[len].
  The argument k is a montgomery context obtained through Hacl_Bignum64_mont_ctx_init.
*/
void
Hacl_Bignum64_mod_precomp(
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k,
  uint64_t *a,
  uint64_t *res
);

/**
Write `a ^ b mod n` in `res`.

  The arguments a and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].
  The argument k is a montgomery context obtained through Hacl_Bignum64_mont_ctx_init.

  The argument b is a bignum of any size, and bBits is an upper bound on the
  number of significant bits of b. A tighter bound results in faster execution
  time. When in doubt, the number of bits for the bignum size is always a safe
  default, e.g. if b is a 4096-bit bignum, bBits should be 4096.

  The function is *NOT* constant-time on the argument b. See the
  mod_exp_consttime_* functions for constant-time variants.

  Before calling this function, the caller will need to ensure that the following
  preconditions are observed.
  • b < pow2 bBits
  • a < n
*/
void
Hacl_Bignum64_mod_exp_vartime_precomp(
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint64_t *res
);

/**
Write `a ^ b mod n` in `res`.

  The arguments a and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].
  The argument k is a montgomery context obtained through Hacl_Bignum64_mont_ctx_init.

  The argument b is a bignum of any size, and bBits is an upper bound on the
  number of significant bits of b. A tighter bound results in faster execution
  time. When in doubt, the number of bits for the bignum size is always a safe
  default, e.g. if b is a 4096-bit bignum, bBits should be 4096.

  This function is constant-time over its argument b, at the cost of a slower
  execution time than mod_exp_vartime_*.

  Before calling this function, the caller will need to ensure that the following
  preconditions are observed.
  • b < pow2 bBits
  • a < n
*/
void
Hacl_Bignum64_mod_exp_consttime_precomp(
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k,
  uint64_t *a,
  uint32_t bBits,
  uint64_t *b,
  uint64_t *res
);

/**
Write `a ^ (-1) mod n` in `res`.

  The argument a and the outparam res are meant to be `len` limbs in size, i.e. uint64_t[len].
  The argument k is a montgomery context obtained through Hacl_Bignum64_mont_ctx_init.

  Before calling this function, the caller will need to ensure that the following
  preconditions are observed.
  • n is a prime
  • 0 < a
  • a < n
*/
void
Hacl_Bignum64_mod_inv_prime_vartime_precomp(
  Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 *k,
  uint64_t *a,
  uint64_t *res
);


/********************/
/* Loads and stores */
/********************/


/**
Load a bid-endian bignum from memory.

  The argument b points to `len` bytes of valid memory.
  The function returns a heap-allocated bignum of size sufficient to hold the
   result of loading b, or NULL if either the allocation failed, or the amount of
    required memory would exceed 4GB.

  If the return value is non-null, clients must eventually call free(3) on it to
  avoid memory leaks.
*/
uint64_t *Hacl_Bignum64_new_bn_from_bytes_be(uint32_t len, uint8_t *b);

/**
Load a little-endian bignum from memory.

  The argument b points to `len` bytes of valid memory.
  The function returns a heap-allocated bignum of size sufficient to hold the
   result of loading b, or NULL if either the allocation failed, or the amount of
    required memory would exceed 4GB.

  If the return value is non-null, clients must eventually call free(3) on it to
  avoid memory leaks.
*/
uint64_t *Hacl_Bignum64_new_bn_from_bytes_le(uint32_t len, uint8_t *b);

/**
Serialize a bignum into big-endian memory.

  The argument b points to a bignum of ⌈len / 8⌉ size.
  The outparam res points to `len` bytes of valid memory.
*/
void Hacl_Bignum64_bn_to_bytes_be(uint32_t len, uint64_t *b, uint8_t *res);

/**
Serialize a bignum into little-endian memory.

  The argument b points to a bignum of ⌈len / 8⌉ size.
  The outparam res points to `len` bytes of valid memory.
*/
void Hacl_Bignum64_bn_to_bytes_le(uint32_t len, uint64_t *b, uint8_t *res);


/***************/
/* Comparisons */
/***************/


/**
Returns 2^64 - 1 if a < b, otherwise returns 0.

 The arguments a and b are meant to be `len` limbs in size, i.e. uint64_t[len].
*/
uint64_t Hacl_Bignum64_lt_mask(uint32_t len, uint64_t *a, uint64_t *b);

/**
Returns 2^64 - 1 if a = b, otherwise returns 0.

 The arguments a and b are meant to be `len` limbs in size, i.e. uint64_t[len].
*/
uint64_t Hacl_Bignum64_eq_mask(uint32_t len, uint64_t *a, uint64_t *b);


#endif  // CRYPTO_HACL_BIGNUM_H_
