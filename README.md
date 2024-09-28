# plain-aes &emsp;[![codecov badge]][codecov link] [![build status badge]][travisci]  [![docs.rs status]][docs.rs]

[docs.rs]: https://docs.rs/plain-aes/latest/
[docs.rs status]: https://img.shields.io/docsrs/plain-aes
[codecov badge]: https://codecov.io/gh/emdCatalyst/plain-aes/graph/badge.svg?token=2W043B5A8G
[codecov link]: https://codecov.io/gh/emdCatalyst/plain-aes
[build status badge]: https://app.travis-ci.com/emdCatalyst/plain-aes.svg?token=DeyV4My8VyqbJ4HAgzPE
[travisci]: https://app.travis-ci.com/emdCatalyst/plain-aes

An implementation of Rijndael's cipher, commonly known as **A**dvanced **E**ncryption **S**tandard.

---

## Features

- Based on [FIPS 197 Final].
- Thoroughly tested and documented.
- Implements AES-128/192 encryption and decryption.
- Implements the following modes of operation:
  - **E**lectronic **C**ode**B**ook.
  - **C**ipher **B**lock **C**haining.
- Ability to implement your own mode of operation, using the block operations exposed by the crate's [internal] module.
- Out of the box support for `&[str]` and `&[u8]` encryption/decryption.
- Ability to encrypt/decrypt any custom data structure that implements the [Encryptable] trait.

[FIPS 197 Final]: https://csrc.nist.gov/pubs/fips/197/final
[Encryptable]: https://docs.rs/plain-aes/latest/plain-aes/trait.Encryptable.html
[internal]: https://docs.rs/plain-aes/latest/plain-aes/internal/index.html

## Test coverage

- This crate is tested using [tarpaulin].
- Currently boasts a 100% line coverage.
- See the project's [codecov page][codecov link] for more information.

[tarpaulin]: https://github.com/xd009642/tarpaulin

## Usage

To use the crate, either add `plain-aes` to your `Cargo.toml`'s dependecies, or run `cargo add plain-aes`.\
Here's a quick example on how to encrypt a text message in AES128-ECB:

```rust
use plain_aes::{encrypt, ModeOfOperation, CipherVersion};
let message = "This is a super secret message";
let key = "This lib is cool"; // This lib is cool
let encrypted_message = encrypt(message, CipherVersion::Aes128(key.as_bytes(), ModeOfOperation::ECB)).unwrap();
let expected_enrypted: &[u8] = &[
   0x11, 0x2B, 0xBD, 0x0D, 0x4C, 0x0C, 0xC5, 0x02, 0xB4, 0xC1, 0x38, 0xFD, 0x9A, 0x56,
    0xC1, 0xA8, 0x78, 0x61, 0xD9, 0xF5, 0x6B, 0x48, 0xCC, 0xC5, 0x48, 0x14, 0xF2, 0x8C,
    0x1A, 0x25, 0x11, 0xA3,
];
assert!(expected_enrypted.iter().eq(encrypted_message.iter()))
```

Refer to [the docs][docs.rs], or the *tests* folder for in-depth examples and documentation.

## License &emsp; [![license]][crates.io]

[license]: https://img.shields.io/crates/l/plain-aes
[crates.io]: https://crates.io/crates/plain-aes

This project is licensed under both the MIT and Apache 2.0 License.
See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

### Disclaimer

> This crate is intended for educational and experimental purposes only and should not be used in production environments. For security-critical applications, it is strongly recommended to use established and well-tested cryptographic libraries that have undergone rigorous security audits.
> The author shall not be liable for any damages, including but not limited to direct, indirect, incidental, special, exemplary, or consequential damages, arising out of or in connection with the use or inability to use this crate.
