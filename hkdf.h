#ifndef HKDF_H
#define HKDF_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct
{
  uint32_t state[8];
  uint64_t bit_len;
  uint8_t buffer[64];
  size_t buffer_len;
} sha256_ctx;

static inline uint32_t sha256_rotr(uint32_t value, uint32_t bits)
{
  return (value >> bits) | (value << (32u - bits));
}

static inline uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) ^ (~x & z);
}

static inline uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sha256_big_sigma0(uint32_t x)
{
  return sha256_rotr(x, 2u) ^ sha256_rotr(x, 13u) ^ sha256_rotr(x, 22u);
}

static inline uint32_t sha256_big_sigma1(uint32_t x)
{
  return sha256_rotr(x, 6u) ^ sha256_rotr(x, 11u) ^ sha256_rotr(x, 25u);
}

static inline uint32_t sha256_small_sigma0(uint32_t x)
{
  return sha256_rotr(x, 7u) ^ sha256_rotr(x, 18u) ^ (x >> 3u);
}

static inline uint32_t sha256_small_sigma1(uint32_t x)
{
  return sha256_rotr(x, 17u) ^ sha256_rotr(x, 19u) ^ (x >> 10u);
}

static inline void sha256_transform(sha256_ctx *ctx, const uint8_t block[64])
{
  static const uint32_t k[64] = {
      0x428a2f98u,
      0x71374491u,
      0xb5c0fbcfu,
      0xe9b5dba5u,
      0x3956c25bu,
      0x59f111f1u,
      0x923f82a4u,
      0xab1c5ed5u,
      0xd807aa98u,
      0x12835b01u,
      0x243185beu,
      0x550c7dc3u,
      0x72be5d74u,
      0x80deb1feu,
      0x9bdc06a7u,
      0xc19bf174u,
      0xe49b69c1u,
      0xefbe4786u,
      0x0fc19dc6u,
      0x240ca1ccu,
      0x2de92c6fu,
      0x4a7484aau,
      0x5cb0a9dcu,
      0x76f988dau,
      0x983e5152u,
      0xa831c66du,
      0xb00327c8u,
      0xbf597fc7u,
      0xc6e00bf3u,
      0xd5a79147u,
      0x06ca6351u,
      0x14292967u,
      0x27b70a85u,
      0x2e1b2138u,
      0x4d2c6dfcu,
      0x53380d13u,
      0x650a7354u,
      0x766a0abbu,
      0x81c2c92eu,
      0x92722c85u,
      0xa2bfe8a1u,
      0xa81a664bu,
      0xc24b8b70u,
      0xc76c51a3u,
      0xd192e819u,
      0xd6990624u,
      0xf40e3585u,
      0x106aa070u,
      0x19a4c116u,
      0x1e376c08u,
      0x2748774cu,
      0x34b0bcb5u,
      0x391c0cb3u,
      0x4ed8aa4au,
      0x5b9cca4fu,
      0x682e6ff3u,
      0x748f82eeu,
      0x78a5636fu,
      0x84c87814u,
      0x8cc70208u,
      0x90befffau,
      0xa4506cebu,
      0xbef9a3f7u,
      0xc67178f2u,
  };

  uint32_t w[64];
  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];
  size_t i = 0;

  for (i = 0; i < 16; ++i)
  {
    w[i] = ((uint32_t)block[i * 4] << 24u) |
           ((uint32_t)block[i * 4 + 1] << 16u) |
           ((uint32_t)block[i * 4 + 2] << 8u) |
           (uint32_t)block[i * 4 + 3];
  }

  for (i = 16; i < 64; ++i)
  {
    w[i] = sha256_small_sigma1(w[i - 2]) + w[i - 7] +
           sha256_small_sigma0(w[i - 15]) + w[i - 16];
  }

  for (i = 0; i < 64; ++i)
  {
    uint32_t temp1 = h + sha256_big_sigma1(e) + sha256_ch(e, f, g) + k[i] + w[i];
    uint32_t temp2 = sha256_big_sigma0(a) + sha256_maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static inline void sha256_init(sha256_ctx *ctx)
{
  ctx->state[0] = 0x6a09e667u;
  ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u;
  ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu;
  ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu;
  ctx->state[7] = 0x5be0cd19u;
  ctx->bit_len = 0;
  ctx->buffer_len = 0;
  memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static inline void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
  size_t offset = 0;

  if (len == 0)
  {
    return;
  }

  ctx->bit_len += (uint64_t)len * 8u;

  if (ctx->buffer_len > 0)
  {
    size_t need = 64u - ctx->buffer_len;
    if (need > len)
    {
      need = len;
    }

    memcpy(ctx->buffer + ctx->buffer_len, data, need);
    ctx->buffer_len += need;
    offset += need;

    if (ctx->buffer_len == 64u)
    {
      sha256_transform(ctx, ctx->buffer);
      ctx->buffer_len = 0;
    }
  }

  while (offset + 64u <= len)
  {
    sha256_transform(ctx, data + offset);
    offset += 64u;
  }

  if (offset < len)
  {
    ctx->buffer_len = len - offset;
    memcpy(ctx->buffer, data + offset, ctx->buffer_len);
  }
}

static inline void sha256_final(sha256_ctx *ctx, uint8_t digest[32])
{
  uint64_t bit_len = ctx->bit_len;
  size_t i = 0;

  ctx->buffer[ctx->buffer_len++] = 0x80u;

  if (ctx->buffer_len > 56u)
  {
    while (ctx->buffer_len < 64u)
    {
      ctx->buffer[ctx->buffer_len++] = 0;
    }
    sha256_transform(ctx, ctx->buffer);
    ctx->buffer_len = 0;
  }

  while (ctx->buffer_len < 56u)
  {
    ctx->buffer[ctx->buffer_len++] = 0;
  }

  for (i = 0; i < 8; ++i)
  {
    ctx->buffer[56u + i] = (uint8_t)(bit_len >> ((7u - i) * 8u));
  }
  sha256_transform(ctx, ctx->buffer);

  for (i = 0; i < 8; ++i)
  {
    digest[i * 4] = (uint8_t)(ctx->state[i] >> 24u);
    digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16u);
    digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8u);
    digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
  }
}

static inline void sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, digest);
}

static inline void hmac_sha256(const uint8_t *key, size_t key_len,
                               const uint8_t *data, size_t data_len,
                               uint8_t digest[32])
{
  uint8_t k0[64];
  uint8_t khash[32];
  uint8_t ipad[64], opad[64];
  uint8_t inner_hash[32];

  if (key_len > 64u)
  {
    sha256(key, key_len, khash);
    key = khash;
    key_len = 32u;
  }

  memset(k0, 0, sizeof(k0));
  memcpy(k0, key, key_len);

  for (size_t i = 0; i < 64u; ++i)
  {
    ipad[i] = k0[i] ^ 0x36u;
    opad[i] = k0[i] ^ 0x5cu;
  }

  sha256_ctx inner_ctx;
  sha256_init(&inner_ctx);
  sha256_update(&inner_ctx, ipad, 64u);
  sha256_update(&inner_ctx, data, data_len);
  sha256_final(&inner_ctx, inner_hash);

  sha256_ctx outer_ctx;
  sha256_init(&outer_ctx);
  sha256_update(&outer_ctx, opad, 64u);
  sha256_update(&outer_ctx, inner_hash, 32u);
  sha256_final(&outer_ctx, digest);
}

static inline int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm, size_t ikm_len,
                              const uint8_t *info, size_t info_len,
                              uint8_t *okm, size_t okm_len)
{
  const size_t hash_len = 32u;
  uint8_t prk[32];
  uint8_t zero_salt[32] = {0};
  uint8_t k0[64];
  uint8_t ipad[64], opad[64];
  uint8_t t[32];
  uint8_t inner_hash[32];
  size_t pos = 0;
  size_t t_len = 0;

  if (okm_len > 255u * hash_len)
  {
    return -1;
  }
  if (okm == NULL && okm_len > 0u)
  {
    return -1;
  }
  if (ikm == NULL && ikm_len > 0u)
  {
    return -1;
  }
  if (info == NULL && info_len > 0u)
  {
    return -1;
  }

  if (salt == NULL || salt_len == 0u)
  {
    salt = zero_salt;
    salt_len = sizeof(zero_salt);
  }

  hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

  memset(k0, 0, sizeof(k0));
  memcpy(k0, prk, sizeof(prk));

  for (size_t i = 0; i < 64u; ++i)
  {
    ipad[i] = k0[i] ^ 0x36u;
    opad[i] = k0[i] ^ 0x5cu;
  }

  for (uint8_t counter = 1u; pos < okm_len; ++counter)
  {
    sha256_ctx inner_ctx;
    sha256_ctx outer_ctx;
    size_t take = okm_len - pos;

    sha256_init(&inner_ctx);
    sha256_update(&inner_ctx, ipad, 64u);
    if (t_len > 0u)
    {
      sha256_update(&inner_ctx, t, t_len);
    }
    if (info != NULL && info_len > 0u)
    {
      sha256_update(&inner_ctx, info, info_len);
    }
    sha256_update(&inner_ctx, &counter, 1u);
    sha256_final(&inner_ctx, inner_hash);

    sha256_init(&outer_ctx);
    sha256_update(&outer_ctx, opad, 64u);
    sha256_update(&outer_ctx, inner_hash, sizeof(inner_hash));
    sha256_final(&outer_ctx, t);

    if (take > hash_len)
    {
      take = hash_len;
    }
    memcpy(okm + pos, t, take);
    pos += take;
    t_len = hash_len;
  }

  return 0;
}

#endif
