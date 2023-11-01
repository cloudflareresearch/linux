/*
 * Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation
 * Copyright (c) 2022-2023 HACL* Contributors
 * Copyright (c) 2023 Cryspen
 */

#ifndef CRYPTO_HACL_LIB_H_
#define CRYPTO_HACL_LIB_H_

#include <asm/unaligned.h>
#include <crypto/sha256_base.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

typedef u128 FStar_UInt128_uint128;

static inline u128 FStar_UInt128_shift_left(u128 x, u32 y)
{
        return (x << y);
}

static inline u128 FStar_UInt128_add(u128 x, u128 y)
{
        return (x + y);
}

static inline u128 FStar_UInt128_uint64_to_uint128(u64 x)
{
        return ((u128)x);
}

inline static u128 FStar_UInt128_mul_wide(u64 x, u64 y) {
  return ((u128) x) * y;
}

inline static u64 FStar_UInt128_uint128_to_uint64(u128 x) {
  return (u64)x;
}

inline static u128 FStar_UInt128_shift_right(u128 x, u32 y) {
  return x >> y;
}

inline static u32 FStar_UInt32_eq_mask(u32 a, u32 b)
{
  u32 x = a ^ b;
  u32 minus_x = ~x + (u32)1U;
  u32 x_or_minus_x = x | minus_x;
  u32 xnx = x_or_minus_x >> (u32)31U;
  return xnx - (u32)1U;
}

inline static u64 FStar_UInt64_eq_mask(u64 a, u64 b)
{
  u64 x = a ^ b;
  u64 minus_x = ~x + (u64)1U;
  u64 x_or_minus_x = x | minus_x;
  u64 xnx = x_or_minus_x >> (u32)63U;
  return xnx - (u64)1U;
}

inline static u32
Hacl_IntTypes_Intrinsics_sub_borrow_u32(u32 cin, u32 x, u32 y, u32 *r)
{
  u64 res = (u64)x - (u64)y - (u64)cin;
  u32 c = (u32)(res >> (u32)32U) & (u32)1U;
  r[0U] = (u32)res;
  return c;
}

inline static u32 FStar_UInt32_gte_mask(u32 a, u32 b)
{
  u32 x = a;
  u32 y = b;
  u32 x_xor_y = x ^ y;
  u32 x_sub_y = x - y;
  u32 x_sub_y_xor_y = x_sub_y ^ y;
  u32 q = x_xor_y | x_sub_y_xor_y;
  u32 x_xor_q = x ^ q;
  u32 x_xor_q_ = x_xor_q >> (u32)31U;
  return x_xor_q_ - (u32)1U;
}

inline static u64 FStar_UInt64_gte_mask(u64 a, u64 b)
{
  u64 x = a;
  u64 y = b;
  u64 x_xor_y = x ^ y;
  u64 x_sub_y = x - y;
  u64 x_sub_y_xor_y = x_sub_y ^ y;
  u64 q = x_xor_y | x_sub_y_xor_y;
  u64 x_xor_q = x ^ q;
  u64 x_xor_q_ = x_xor_q >> (u32)63U;
  return x_xor_q_ - (u64)1U;
}


inline static u32
Hacl_IntTypes_Intrinsics_add_carry_u32(u32 cin, u32 x, u32 y, u32 *r)
{
  u64 res = (u64)x + (u64)cin + (u64)y;
  u32 c = (u32)(res >> (u32)32U);
  r[0U] = (u32)res;
  return c;
}

inline static u128 FStar_UInt128_add_mod(u128 x, u128 y) {
  return x + y;
}

inline static u128 FStar_UInt128_sub_mod(u128 x, u128 y) {
  return x - y;
}

inline static u64
Hacl_IntTypes_Intrinsics_128_add_carry_u64(u64 cin, u64 x, u64 y, u64 *r)
{
  FStar_UInt128_uint128
  res =
    FStar_UInt128_add_mod(FStar_UInt128_add_mod(FStar_UInt128_uint64_to_uint128(x),
        FStar_UInt128_uint64_to_uint128(cin)),
      FStar_UInt128_uint64_to_uint128(y));
  u64 c = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(res, (u32)64U));
  r[0U] = FStar_UInt128_uint128_to_uint64(res);
  return c;
}

inline static u64
Hacl_IntTypes_Intrinsics_128_sub_borrow_u64(u64 cin, u64 x, u64 y, u64 *r)
{
  FStar_UInt128_uint128
  res =
    FStar_UInt128_sub_mod(FStar_UInt128_sub_mod(FStar_UInt128_uint64_to_uint128(x),
        FStar_UInt128_uint64_to_uint128(y)),
      FStar_UInt128_uint64_to_uint128(cin));
  u64
  c =
    FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(res, (u32)64U))
    & (u64)1U;
  r[0U] = FStar_UInt128_uint128_to_uint64(res);
  return c;
}

#define Lib_IntTypes_Intrinsics_sub_borrow_u32(x1, x2, x3, x4) \
    (Hacl_IntTypes_Intrinsics_sub_borrow_u32(x1, x2, x3, x4))

#define Lib_IntTypes_Intrinsics_add_carry_u32(x1, x2, x3, x4) \
  (Hacl_IntTypes_Intrinsics_add_carry_u32(x1, x2, x3, x4))

#define Lib_IntTypes_Intrinsics_add_carry_u64(x1, x2, x3, x4) \
    (Hacl_IntTypes_Intrinsics_128_add_carry_u64(x1, x2, x3, x4))

#define Lib_IntTypes_Intrinsics_sub_borrow_u64(x1, x2, x3, x4) \
    (Hacl_IntTypes_Intrinsics_128_sub_borrow_u64(x1, x2, x3, x4))

/*
 * Loads and stores. These avoid undefined behavior due to unaligned memory
 * accesses, via memcpy.
 */

#define load32_be(b)     (get_unaligned_be32(b))
#define store32_be(b, i) put_unaligned_be32(i, b);
#define load64_be(b)     (get_unaligned_be64(b))
#define store64_be(b, i) put_unaligned_be64(i, b);

#define load32_le(b)     (get_unaligned_le32(b))
#define store32_le(b, i) put_unaligned_le32(i, b);
#define load64_le(b)     (get_unaligned_le64(b))
#define store64_le(b, i) put_unaligned_le64(i, b);

static inline void store128_be(u8 *buf, u128 x)
{
        store64_be(buf, (u64)(x >> 64));
        store64_be(buf + 8, (u64)(x));
}

/* Macros for prettier unrolling of loops */
#define KRML_LOOP1(i, n, x) \
        {                   \
                x i += n;   \
        }

#define KRML_LOOP2(i, n, x) \
        KRML_LOOP1(i, n, x) \
        KRML_LOOP1(i, n, x)

#define KRML_LOOP3(i, n, x) \
        KRML_LOOP2(i, n, x) \
        KRML_LOOP1(i, n, x)

#define KRML_LOOP4(i, n, x) \
        KRML_LOOP2(i, n, x) \
        KRML_LOOP2(i, n, x)

#define KRML_LOOP5(i, n, x) \
        KRML_LOOP4(i, n, x) \
        KRML_LOOP1(i, n, x)

#define KRML_LOOP6(i, n, x) \
        KRML_LOOP4(i, n, x) \
        KRML_LOOP2(i, n, x)

#define KRML_LOOP7(i, n, x) \
        KRML_LOOP4(i, n, x) \
        KRML_LOOP3(i, n, x)

#define KRML_LOOP8(i, n, x) \
        KRML_LOOP4(i, n, x) \
        KRML_LOOP4(i, n, x)

#define KRML_LOOP9(i, n, x) \
        KRML_LOOP8(i, n, x) \
        KRML_LOOP1(i, n, x)

#define KRML_LOOP10(i, n, x) \
        KRML_LOOP8(i, n, x)  \
        KRML_LOOP2(i, n, x)

#define KRML_LOOP11(i, n, x) \
        KRML_LOOP8(i, n, x)  \
        KRML_LOOP3(i, n, x)

#define KRML_LOOP12(i, n, x) \
        KRML_LOOP8(i, n, x)  \
        KRML_LOOP4(i, n, x)

#define KRML_LOOP13(i, n, x) \
        KRML_LOOP8(i, n, x)  \
        KRML_LOOP5(i, n, x)

#define KRML_LOOP14(i, n, x) \
        KRML_LOOP8(i, n, x)  \
        KRML_LOOP6(i, n, x)

#define KRML_LOOP15(i, n, x) \
        KRML_LOOP8(i, n, x)  \
        KRML_LOOP7(i, n, x)

#define KRML_LOOP16(i, n, x) \
        KRML_LOOP8(i, n, x)  \
        KRML_LOOP8(i, n, x)

#define KRML_UNROLL_FOR(i, z, n, k, x) \
        do {                           \
                uint32_t i = z;        \
                KRML_LOOP##n(i, k, x)  \
        } while (0)

#define KRML_ACTUAL_FOR(i, z, n, k, x)                \
        do {                                          \
                for (uint32_t i = z; i < n; i += k) { \
                        x                             \
                }                                     \
        } while (0)

#define KRML_UNROLL_MAX 16

/* 1 is the number of loop iterations, i.e. (n - z)/k as evaluated by krml */
#if 0 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR0(i, z, n, k, x)
#else
#define KRML_MAYBE_FOR0(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 1 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR1(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 1, k, x)
#else
#define KRML_MAYBE_FOR1(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 2 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR2(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 2, k, x)
#else
#define KRML_MAYBE_FOR2(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 3 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR3(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 3, k, x)
#else
#define KRML_MAYBE_FOR3(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 4 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR4(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 4, k, x)
#else
#define KRML_MAYBE_FOR4(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 5 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR5(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 5, k, x)
#else
#define KRML_MAYBE_FOR5(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 6 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR6(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 6, k, x)
#else
#define KRML_MAYBE_FOR6(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 7 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR7(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 7, k, x)
#else
#define KRML_MAYBE_FOR7(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 8 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR8(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 8, k, x)
#else
#define KRML_MAYBE_FOR8(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 9 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR9(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 9, k, x)
#else
#define KRML_MAYBE_FOR9(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 10 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR10(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 10, k, x)
#else
#define KRML_MAYBE_FOR10(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 11 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR11(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 11, k, x)
#else
#define KRML_MAYBE_FOR11(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 12 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR12(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 12, k, x)
#else
#define KRML_MAYBE_FOR12(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 13 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR13(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 13, k, x)
#else
#define KRML_MAYBE_FOR13(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 14 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR14(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 14, k, x)
#else
#define KRML_MAYBE_FOR14(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 15 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR15(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 15, k, x)
#else
#define KRML_MAYBE_FOR15(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#if 16 <= KRML_UNROLL_MAX
#define KRML_MAYBE_FOR16(i, z, n, k, x) KRML_UNROLL_FOR(i, z, 16, k, x)
#else
#define KRML_MAYBE_FOR16(i, z, n, k, x) KRML_ACTUAL_FOR(i, z, n, k, x)
#endif

#ifndef KRML_HOST_IGNORE
#define KRML_HOST_IGNORE(x) (void)(x)
#endif

// XXX [FK]: Do we want the macro?
#define KRML_CHECK_SIZE(size_elt, sz)

#define alloca(x) kzalloc((x), GFP_KERNEL)
#define KRML_HOST_CALLOC(l, s) kzalloc((l) * s, GFP_KERNEL)
#define KRML_HOST_MALLOC(x) kzalloc((x), GFP_KERNEL)
#define KRML_HOST_FREE(x) kfree((x))

#endif  // CRYPTO_HACL_LIB_H_
