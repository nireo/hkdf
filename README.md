# hkdf

Single-header SHA-256, HMAC-SHA256, and HKDF-SHA256 implementation.

## Build and run tests

```sh
make test
```

## HKDF usage

```c
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "hkdf.h"

int main(void) {
  const uint8_t *input_key_material = (const uint8_t *)"my-master-secret";
  const size_t input_key_material_len =
      strlen((const char *)input_key_material);

  const uint8_t *salt = (const uint8_t *)"service-A salt";
  const size_t salt_len = strlen((const char *)salt);

  const uint8_t *context_info = (const uint8_t *)"aes-256-gcm key";
  const size_t context_info_len = strlen((const char *)context_info);

  uint8_t output_key_material[32];
  return hkdf_sha256(
      salt, salt_len, input_key_material, input_key_material_len, context_info,
      context_info_len, output_key_material, sizeof(output_key_material));
}
```

`hkdf_sha256(...)` returns `0` on success and `-1` for invalid inputs.
