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

  if (!ok) {
    return 1;
  }

  printf("sha256 tests passed\n");
  return 0;
}
