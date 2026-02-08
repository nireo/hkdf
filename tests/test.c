#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../hkdf.h"

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
  size_t hex_len = strlen(hex);
  size_t i = 0;

  if (hex_len != out_len * 2u) {
    return 0;
  }

  for (i = 0; i < out_len; ++i) {
    int hi = hex_nibble(hex[i * 2]);
    int lo = hex_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return 0;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }

  return 1;
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  size_t i = 0;
  for (i = 0; i < len; ++i) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

static void print_hex(const uint8_t *data, size_t len) {
  size_t i = 0;
  for (i = 0; i < len; ++i) {
    printf("%02x", data[i]);
  }
}

static int test_vector(const char *label, const uint8_t *msg, size_t msg_len,
                       const char *expected_hex) {
  uint8_t expected[32];
  uint8_t one_shot[32];
  uint8_t chunked[32];
  sha256_ctx ctx;
  size_t offset = 0;
  size_t chunk_size = 7;

  if (!hex_to_bytes(expected_hex, expected, sizeof(expected))) {
    fprintf(stderr, "invalid expected hash for %s\n", label);
    return 0;
  }

  sha256(msg, msg_len, one_shot);
  if (!bytes_equal(one_shot, expected, sizeof(expected))) {
    fprintf(stderr, "one-shot mismatch for %s\nexpected: ", label);
    print_hex(expected, sizeof(expected));
    fprintf(stderr, "\nactual:   ");
    print_hex(one_shot, sizeof(one_shot));
    fprintf(stderr, "\n");
    return 0;
  }

  sha256_init(&ctx);
  while (offset < msg_len) {
    size_t remaining = msg_len - offset;
    size_t take = remaining < chunk_size ? remaining : chunk_size;
    sha256_update(&ctx, msg + offset, take);
    offset += take;
    chunk_size = (chunk_size % 13u) + 1u;
  }
  sha256_final(&ctx, chunked);

  if (!bytes_equal(chunked, expected, sizeof(expected))) {
    fprintf(stderr, "chunked mismatch for %s\nexpected: ", label);
    print_hex(expected, sizeof(expected));
    fprintf(stderr, "\nactual:   ");
    print_hex(chunked, sizeof(chunked));
    fprintf(stderr, "\n");
    return 0;
  }

  return 1;
}

static int test_million_a(void) {
  uint8_t expected[32];
  uint8_t digest[32];
  uint8_t chunk[1000];
  sha256_ctx ctx;
  size_t i = 0;

  memset(chunk, 'a', sizeof(chunk));

  if (!hex_to_bytes(
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
          expected, sizeof(expected))) {
    return 0;
  }

  sha256_init(&ctx);
  for (i = 0; i < 1000; ++i) {
    sha256_update(&ctx, chunk, sizeof(chunk));
  }
  sha256_final(&ctx, digest);

  if (!bytes_equal(digest, expected, sizeof(expected))) {
    fprintf(stderr, "million-a mismatch\nexpected: ");
    print_hex(expected, sizeof(expected));
    fprintf(stderr, "\nactual:   ");
    print_hex(digest, sizeof(digest));
    fprintf(stderr, "\n");
    return 0;
  }

  return 1;
}

static int test_hkdf_case_1(void) {
  uint8_t ikm[22];
  uint8_t salt[13];
  uint8_t info[10];
  uint8_t prk[32];
  uint8_t okm[42];
  uint8_t expected_prk[32];
  uint8_t expected_okm[42];
  size_t i = 0;

  memset(ikm, 0x0b, sizeof(ikm));
  for (i = 0; i < sizeof(salt); ++i) {
    salt[i] = (uint8_t)i;
  }
  for (i = 0; i < sizeof(info); ++i) {
    info[i] = (uint8_t)(0xf0u + i);
  }

  if (!hex_to_bytes(
          "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
          expected_prk, sizeof(expected_prk))) {
    return 0;
  }
  if (!hex_to_bytes(
          "3cb25f25faacd57a90434f64d0362f2a"
          "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          "34007208d5b887185865",
          expected_okm, sizeof(expected_okm))) {
    return 0;
  }

  hmac_sha256(salt, sizeof(salt), ikm, sizeof(ikm), prk);
  if (!bytes_equal(prk, expected_prk, sizeof(expected_prk))) {
    fprintf(stderr, "hkdf case 1 PRK mismatch\nexpected: ");
    print_hex(expected_prk, sizeof(expected_prk));
    fprintf(stderr, "\nactual:   ");
    print_hex(prk, sizeof(prk));
    fprintf(stderr, "\n");
    return 0;
  }

  if (hkdf_sha256(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm,
                  sizeof(okm)) != 0) {
    fprintf(stderr, "hkdf case 1 returned error\n");
    return 0;
  }
  if (!bytes_equal(okm, expected_okm, sizeof(expected_okm))) {
    fprintf(stderr, "hkdf case 1 OKM mismatch\nexpected: ");
    print_hex(expected_okm, sizeof(expected_okm));
    fprintf(stderr, "\nactual:   ");
    print_hex(okm, sizeof(okm));
    fprintf(stderr, "\n");
    return 0;
  }

  return 1;
}

static int test_hkdf_case_2(void) {
  uint8_t ikm[80];
  uint8_t salt[80];
  uint8_t info[80];
  uint8_t prk[32];
  uint8_t okm[82];
  uint8_t expected_prk[32];
  uint8_t expected_okm[82];
  size_t i = 0;

  for (i = 0; i < sizeof(ikm); ++i) {
    ikm[i] = (uint8_t)i;
    salt[i] = (uint8_t)(0x60u + i);
    info[i] = (uint8_t)(0xb0u + i);
  }

  if (!hex_to_bytes(
          "06a6b88c5853361a06104c9ceb35b45c"
          "ef760014904671014a193f40c15fc244",
          expected_prk, sizeof(expected_prk))) {
    return 0;
  }
  if (!hex_to_bytes(
          "b11e398dc80327a1c8e7f78c596a4934"
          "4f012eda2d4efad8a050cc4c19afa97c"
          "59045a99cac7827271cb41c65e590e09"
          "da3275600c2f09b8367793a9aca3db71"
          "cc30c58179ec3e87c14c01d5c1f3434f"
          "1d87",
          expected_okm, sizeof(expected_okm))) {
    return 0;
  }

  hmac_sha256(salt, sizeof(salt), ikm, sizeof(ikm), prk);
  if (!bytes_equal(prk, expected_prk, sizeof(expected_prk))) {
    fprintf(stderr, "hkdf case 2 PRK mismatch\nexpected: ");
    print_hex(expected_prk, sizeof(expected_prk));
    fprintf(stderr, "\nactual:   ");
    print_hex(prk, sizeof(prk));
    fprintf(stderr, "\n");
    return 0;
  }

  if (hkdf_sha256(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm,
                  sizeof(okm)) != 0) {
    fprintf(stderr, "hkdf case 2 returned error\n");
    return 0;
  }
  if (!bytes_equal(okm, expected_okm, sizeof(expected_okm))) {
    fprintf(stderr, "hkdf case 2 OKM mismatch\nexpected: ");
    print_hex(expected_okm, sizeof(expected_okm));
    fprintf(stderr, "\nactual:   ");
    print_hex(okm, sizeof(okm));
    fprintf(stderr, "\n");
    return 0;
  }

  return 1;
}

static int test_hkdf_case_3(void) {
  uint8_t ikm[22];
  uint8_t prk[32];
  uint8_t okm[42];
  uint8_t expected_prk[32];
  uint8_t expected_okm[42];
  uint8_t zero_salt[32] = {0};

  memset(ikm, 0x0b, sizeof(ikm));

  if (!hex_to_bytes(
          "19ef24a32c717b167f33a91d6f648bdf"
          "96596776afdb6377ac434c1c293ccb04",
          expected_prk, sizeof(expected_prk))) {
    return 0;
  }
  if (!hex_to_bytes(
          "8da4e775a563c18f715f802a063c5a31"
          "b8a11f5c5ee1879ec3454e5f3c738d2d"
          "9d201395faa4b61a96c8",
          expected_okm, sizeof(expected_okm))) {
    return 0;
  }

  hmac_sha256(zero_salt, 0, ikm, sizeof(ikm), prk);
  if (!bytes_equal(prk, expected_prk, sizeof(expected_prk))) {
    fprintf(stderr, "hkdf case 3 PRK mismatch\nexpected: ");
    print_hex(expected_prk, sizeof(expected_prk));
    fprintf(stderr, "\nactual:   ");
    print_hex(prk, sizeof(prk));
    fprintf(stderr, "\n");
    return 0;
  }

  if (hkdf_sha256(NULL, 0, ikm, sizeof(ikm), NULL, 0, okm, sizeof(okm)) != 0) {
    fprintf(stderr, "hkdf case 3 returned error\n");
    return 0;
  }
  if (!bytes_equal(okm, expected_okm, sizeof(expected_okm))) {
    fprintf(stderr, "hkdf case 3 OKM mismatch\nexpected: ");
    print_hex(expected_okm, sizeof(expected_okm));
    fprintf(stderr, "\nactual:   ");
    print_hex(okm, sizeof(okm));
    fprintf(stderr, "\n");
    return 0;
  }

  return 1;
}

int main(void) {
  int ok = 1;
  const char *abc = "abc";
  const char *long_vec = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

  ok &= test_vector("empty", (const uint8_t *)"", 0,
                    "e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855");
  ok &= test_vector("abc", (const uint8_t *)abc, strlen(abc),
                    "ba7816bf8f01cfea414140de5dae2223"
                    "b00361a396177a9cb410ff61f20015ad");
  ok &= test_vector("long", (const uint8_t *)long_vec, strlen(long_vec),
                    "248d6a61d20638b8e5c026930c3e6039"
                    "a33ce45964ff2167f6ecedd419db06c1");
  ok &= test_million_a();
  ok &= test_hkdf_case_1();
  ok &= test_hkdf_case_2();
  ok &= test_hkdf_case_3();

  if (!ok) {
    return 1;
  }

  printf("sha256 and hkdf tests passed\n");
  return 0;
}
