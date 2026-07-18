# XAES-256-GCM in C

A C implementation of [XAES-256-GCM][1], an extended-nonce authenticated
encryption with associated Data (AEAD) algorithm, and its key-committing
variant [KC-XAES-256-GCM][2].

Both variants are compatible with NIST standards and can be considered a
composition of key derivation using the standard CMAC-based KDF and
AES-256-GCM.

This implementation uses only public platform APIs for cryptographic
operations via one of the backends.

## Backends

* CryptoKit + CommonCrypto (macOS, iOS)
* OpenSSL (Linux, FreeBSD)
* LibreSSL (OpenBSD)
* BoringSSL

## Building

Each backend has its own Makefile._backend_. The default `Makefile` will try to
autodetect the platform and use the correct Makefile._backend_, so you can just
run `make` in most cases.

**macOS, Linux, OpenBSD, FreeBSD:**

```
make
```

(Note that the macOS/iOS version, `Makefile.apple`, requires the Swift compiler
because it needs to build the CryptoKit shim for AES-GCM.)

This will create a directory `dist` with:

- `include/xaes256gcm.h` -- public API
- `include/xaes256gcm_platform.h` -- platform support file, included from `xaes256gcm.h`
- `libxaes256gcm.a` -- static library
- `test` -- test executable
- `benchmark` -- benchmark executable

Alternatively, just copy the needed .c, .h files into your project
(renaming the suitable `xaes256gcm_backend.h` into `xaes256gcm_platform.h`).


**BoringSSL:**

Fetch and then build BoringSSL in a path of your choice:

```
# inside boringssl directory
mkdir build
cd build
cmake ..
make
```

```
# inside xaes256gcm directory
make -f Makefile.boringssl BORINGSSL_DIR=/path/to/boringssl
```

**LibreSSL Portable:**

On macOS, install LibreSSL with Homebrew:

```
brew install libressl

LDFLAGS="-L/opt/homebrew/opt/libressl/lib" \
CFLAGS="-I/opt/homebrew/opt/libressl/include" \
make -f Makefile.libressl
```


## Performance

XAES-GCM adds just a little overhead to AES-GCM: two additional block
encryptions and a key schedule per message. The key committing variant adds
three more block encryptions per message.

On M1 MacBook Air BoringSSL backend encrypts 1 MB messages at 6.3 GB/s, Apple
backend at 4.7 GB/s, and OpenSSL backend in Linux and FreeBSD VMs at 5.5 GB/s.
(LibreSSL doesn't have AES instruction support for arm64 yet).

On AMD EPYC-Genoa in a Linux VM, OpenSSL backend encrypts 1 MB messages
at 11 GB/s.

## Security

- Nonce reuse breaks both confidentiality and authenticity. Every key, nonce
  pair must be unique.
- The 192-bit nonce makes random nonce generation safe.
- The key-committing variant binds each ciphertext to one specific key,
  preventing attacks where an adversary can generate a single ciphertext that
  decrypts successfully under multiple keys into different plaintexts.

## API

All functions (except for `xaes256gcm_ctx_destroy`) return 0 on success, nonzero on error.
Their result MUST be checked.

### Constants

- `XAES256GCM_KEY_SIZE`    (32) -- key length in bytes
- `XAES256GCM_NONCE_SIZE`  (24) -- nonce length in bytes
- `XAES256GCM_OVERHEAD`    (16) -- ciphertext overhead (authentication tag)
- `XAES256GCM_KC_OVERHEAD` (48) -- KC variant ciphertext overhead (tag + 32-byte key commitment)
- `XAES256GCM_AAD_MAX` -- maximum size of associated data in bytes
  (minimum of 2^61 - 1 and SIZE_MAX).
- `XAES256GCM_PLAINTEXT_MAX` -- maximum size of plaintext in bytes
  (minimum of 2^36 - 32 and SIZE_MAX - 48).

### Context

Usage:

```c
// allocate context (e.g. on stack)
struct xaes256gcm_ctx c;

// initialize context
if (xaes256gcm_ctx_init(&c, key) != 0) {
    // handle error
}

// use c for seal/open...

// destroy context
xaes256gcm_ctx_destroy(&c);
```

Each seal and open operation is semantically independent.
However, the context is NOT thread-safe: each thread should create its own.

If you don't want to manage context manually and don't need the slight
performance improvement from caching the key for multiple operations, use the
one-shot functions described later.

#### `xaes256gcm_ctx_init`

```c
int xaes256gcm_ctx_init(struct xaes256gcm_ctx *c, const uint8_t key[32]);
```

Initialize the context with the 32-byte secret key.

Every context initialized with `xaes256gcm_ctx_init()` must be disposed of
with `xaes256gcm_ctx_destroy()`. Depending on the backend, the initialization
may allocate memory, which is freed by the destructor.

Returns 0 on success, nonzero on error.
An error indicates that the underlying crypto backend failed to initialize.


#### `xaes256gcm_ctx_destroy`

```c
void xaes256gcm_ctx_destroy(struct xaes256gcm_ctx *c);
```

Dispose of the context.

### Encryption and decryption

#### `xaes256gcm_ctx_seal`

```c
int xaes256gcm_ctx_seal(
    struct xaes256gcm_ctx *c,
    const uint8_t nonce[24],
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t ciphertext_max_len
);
```

Encrypt and authenticate the plaintext, authenticate the optional additional
data, and write the result to ciphertext. The `ciphertext_max_len` indicates the
space available for the result, which must be at least `plaintext_len +
XAES256GCM_OVERHEAD`.

The nonce must be unique for this key. It doesn't need to be random or
unpredictable, however random nonces are allowed. 
Reusing a nonce with the same key breaks confidentiality and authenticity.

Returns 0 on success, nonzero on error.

An error indicates that the underlying crypto backend failed to encrypt, or
the input bounds are not satisfied. On error, the state of the resulting
ciphertext is undefined.

#### `xaes256gcm_ctx_open`

```c
int xaes256gcm_ctx_open(
    struct xaes256gcm_ctx *c,
    const uint8_t nonce[24],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t plaintext_max_len
);
```

Verify authentication tag in the ciphertext and decrypt ciphertext.
The `plaintext_max_len` indicates the space avilable for the
result, which must be at least `ciphertext_len - XAES256GCM_OVERHEAD`.

The nonce and additional data must be the same as given to the seal function.

Returns 0 on success, nonzero on error.

An error indicates that the underlying crypto backend failed to decrypt, the
input bounds are not satisfied, or ciphertext authentication failed. On
error, the resulting plaintext is undefined and may be overwritten with
zeros, but will not contain partially decrypted data if authentication
fails.

#### `xaes256gcm_ctx_seal_kc`

```c
int xaes256gcm_ctx_seal_kc(
    struct xaes256gcm_ctx *c,
    const uint8_t nonce[24],
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t ciphertext_max_len
);
```

Same as `xaes256gcm_ctx_seal` but also computes a 32-byte key commitment tag appended
after the authentication tag. Output is `plaintext_len + XAES256GCM_KC_OVERHEAD`
(plaintext + 48 bytes).

#### `xaes256gcm_ctx_open_kc`

```c
int xaes256gcm_ctx_open_kc(
    struct xaes256gcm_ctx *c,
    const uint8_t nonce[24],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t plaintext_max_len
);
```

Same as `xaes256gcm_ctx_open`, but also verifies key commitment.
`plaintext_max_len` must be at least `ciphertext_len - XAES256GCM_KC_OVERHEAD`.

### Simple one-shot functions

These combine `init` + `seal`/`open` + `destroy` in a single call.

```c
int xaes256gcm_seal(
    const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t ciphertext_max_len
);

int xaes256gcm_open(
    const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t plaintext_max_len
);

int xaes256gcm_seal_kc(
    const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t ciphertext_max_len
);

int xaes256gcm_open_kc(
    const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t plaintext_max_len
);
```

### Nonce generation

#### `xaes256gcm_rand_nonce`

```c
int xaes256gcm_rand_nonce(uint8_t nonce[24]);
```

Generate a random 24-byte nonce using the backend's CSPRNG.

Returns 0 on success, nonzero on error.

An error indicates that the underlying crypto backend failed to generate
random bytes, and the contents of the nonce is undefined.


## Example

```c
#include <string.h>
#include <stdio.h>

#include <xaes256gcm.h>

int main(void)
{
    uint8_t key[32] = {0}; // fill with an actual secret key
    uint8_t nonce[24];
    uint8_t plaintext[] = "Hello, world!"; // includes NUL
    uint8_t ciphertext[sizeof(plaintext) - 1 + XAES256GCM_OVERHEAD];
    uint8_t decrypted[sizeof(plaintext)] = {0};
    uint8_t aad[] = "metadata"; // includes NUL

    struct xaes256gcm_ctx c;

    // Initialize context.
    if (xaes256gcm_ctx_init(&c, key) != 0) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    // Generate a random nonce.
    if (xaes256gcm_rand_nonce(nonce) != 0) {
        fprintf(stderr, "nonce generation failed\n");
        xaes256gcm_ctx_destroy(&c);
        return 1;
    }

    // Encrypt.
    if (xaes256gcm_ctx_seal(&c, nonce,
            plaintext, sizeof(plaintext) - 1,
            aad, sizeof(aad) - 1,
            ciphertext, sizeof(ciphertext)) != 0) {
        fprintf(stderr, "encryption failed\n");
        xaes256gcm_ctx_destroy(&c);
        return 1;
    }

    // Decrypt.
    if (xaes256gcm_ctx_open(&c, nonce,
            ciphertext, sizeof(ciphertext),
            aad, sizeof(aad) - 1,
            decrypted, sizeof(decrypted)) != 0) {
        fprintf(stderr, "decryption failed\n");
        xaes256gcm_ctx_destroy(&c);
        return 2;
    }

    printf("%s\n", decrypted); // "Hello, world!"

    xaes256gcm_ctx_destroy(&c);
    return 0;
}
```

To build and run it, place `example.c` into `dist` and then run:

```
cc example.c -o example -Iinclude -L. -lxaes256gcm && ./example
```

Note that unlike this simple example, to encrypt text
you should first encode it appropriately into bytes as UTF-8.

## References

- [XAES-256-GCM specification][1]
- [Filippo Valsorda: XAES-256-GCM][3]
- [Blockcipher-Based Key Commitment for Nonce-Derived Schemes][2]

## License

ISC License. See [LICENSE](LICENSE).

[1]: https://c2sp.org/XAES-256-GCM
[2]: https://eprint.iacr.org/2025/758
[3]: https://words.filippo.io/dispatches/xaes-256-gcm/
