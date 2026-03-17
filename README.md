# ender-eye

<p align="center">
  <img src="https://art.pixilart.com/sr281c51b66f4aws3.png" alt="Ender Eye" width="120" />
</p>

[![Crates.io](https://img.shields.io/crates/v/ender-eye)](https://crates.io/crates/ender-eye)
[![docs.rs](https://img.shields.io/docsrs/ender-eye)](https://docs.rs/ender-eye)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust edition](https://img.shields.io/badge/rust%20edition-2021-orange.svg)](https://doc.rust-lang.org/edition-guide/)

A Rust library for encrypting and decrypting messages through a transformation pipeline using the Standard Galactic Alphabet from Minecraft : SGA encoding → AES-256-GCM → Base64. Give it a message and a password, and you get back an opaque payload that no one can read without that password.

---

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ender-eye = "1.0.0"
```

---

## Quick start

```rust
use ender_eye::{encrypt, decrypt};

fn main() {
    let ciphertext = encrypt("hello world", "my-secret-password").unwrap();
    let plaintext  = decrypt(&ciphertext,   "my-secret-password").unwrap();

    assert_eq!(plaintext, "hello world");
}
```

---

## Security decisions

### Why Argon2id instead of using the password directly?

Human-chosen passwords are weak by nature: short, predictable, reused. If we used the password as the AES key directly, an attacker could try millions of candidates per second on commodity hardware. Argon2id is a key derivation function (KDF) designed to be **deliberately expensive** in both time and memory, making each brute-force attempt cost real resources. It also stretches any password, regardless of length, into exactly the 32 bytes AES-256 requires.

### Why AES-256-GCM instead of a simpler cipher?

AES-256-GCM is authenticated encryption (AEAD): it does not just hide the content, it also **detects whether the ciphertext was tampered with**. A "simpler" cipher like AES-CBC encrypts data but does not authenticate it, opening the door to padding oracle attacks and bit-flipping. With GCM, if anyone modifies even a single byte of the payload, decryption fails with an explicit error instead of silently returning garbage.

### Why random salt and nonce?

Both ensure that **encrypting the same message with the same password always produces a different output**:

- **Salt**: mixed with the password before Argon2 runs, making the derived key unique per encryption call. Without a random salt, two users sharing the same password would produce the same key.
- **Nonce** (number used once): the initialization vector for GCM mode. Reusing a nonce with the same key catastrophically breaks the cipher and can expose the key. Generating it randomly each time makes collisions negligible.

Both values are stored in plaintext inside the payload — they are not secret. Their only job is to add uniqueness, not confidentiality.

---

## Internal pipeline

```
encrypt("hello", "pass")
    │
    ├─ SGA encode      →  "hello" → "⊣↸ꖎꖎ𝙹"  (character substitution)
    ├─ Argon2id        →  derive 32-byte key   (password + random salt)
    ├─ AES-256-GCM     →  encrypt SGA-encoded bytes  (random nonce)
    └─ Base64 encode   →  salt || nonce || ciphertext → opaque string
```

---

## License

MIT

---

## Disclaimer

"Ender Eye" and the Standard Galactic Alphabet are trademarks of Mojang Studios. This project is not affiliated with or endorsed by Mojang Studios.

---

## Credits

Ender Eye pixel art by [da-l3af](https://www.pixilart.com/art/ender-eye-sr281c51b66f4aws3) on Pixilart.
