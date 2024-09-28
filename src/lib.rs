//! # plain-aes
//!
//! This crate implements Rijndael's cipher, in 128 bits and 192 bits modes respectively.
//!
//! ## Considerations
//! * Within this crate, "block" or "block of data" refers specifically to a 16-byte sequence, as defined in the [FIPS 197 specification](https://csrc.nist.gov/pubs/fips/197/final).
//! * For efficiency, most affine transformations and operations within GF(2^8) (e.g., polynomial multiplication) are implemented using pre-computed lookup tables.
//! * While this crate is comprehensively tested, it should not be used in security-critical applications due to potential vulnerabilities. Modern CPUs offer hardware-accelerated AES, and some even have dedicated cryptographic coprocessors. These hardware features provide a more secure and performant solution for critical applications.
//! ## Getting started
//! 1. Run `cargo add plain-aes` or add `plain-aes` to your `Cargo.toml`.
//! 2. Copy one of the examples included in [encrypt]/[decrypt], or refer to the tests folder in the Github repo to get started.
pub use internal::KeyExpansionError;
use internal::{decrypt_block, encrypt_block, ExpandedKey};
/// This module encapsulates all internal operations for this crate.
pub mod internal;
/// A trait implemented by types that can be used as input for encryption or decryption operations.
///
/// This trait provides a unified interface for different data types, allowing you to pass them directly to the encryption/decryption algorithm without requiring additional logic.
///
/// For example, you could implement this trait on a file handle to encrypt or decrypt the contents of a file directly.
///
/// # Examples
///
/// ```
/// use plain_aes::{encrypt, Encryptable, CipherVersion, ModeOfOperation};
/// struct MyData {
///     content: String,
/// }
///
/// impl Encryptable for MyData {
///     fn data(&self) -> Option<&[u8]> {
///         Some(self.content.as_bytes())
///     }
/// }
///
/// let data = MyData { content: "example usage of Encryptable".to_string() };
/// let encrypted_data = encrypt(data, CipherVersion::Aes128("This lib is cool".as_bytes(), ModeOfOperation::ECB));
/// ```
pub trait Encryptable {
    /// Returns a dynamic slice containing the byte sequence of the content to be encrypted.
    fn data(&self) -> Option<&[u8]>;
}
/// Mode of operation for AES.
pub enum ModeOfOperation<'a> {
    CBC(&'a [u8]),
    ECB,
}
/// The cipher version to use, each cipher version encapsulates a key and [ModeOfOperation].
pub enum CipherVersion<'a> {
    Aes128(&'a [u8], ModeOfOperation<'a>),
    Aes192(&'a [u8], ModeOfOperation<'a>),
}
/// An error produced during an encryption/decryption.
#[derive(Debug, PartialEq)]
pub enum OperationError {
    /// The key expansion failed.
    KeyExpansionFailed(KeyExpansionError),
    /// The provided target had no data.
    EmptyTarget,
    /// The given target's data is less than the block size for AES, and thus cannot be fed to the encryption/decryption algorithm.
    ///
    /// For decryption, the target's data is most likely not a result of an AES encryption.
    ///
    /// For encryption, consider applying [pkcs5_padding] to the target's data before using [encrypt].
    InvalidTargetSize,
}
impl<'a> CipherVersion<'a> {
    /// Returns the expanded key size of each cipher version.
    fn expanded_key_size(&self) -> usize {
        match self {
            CipherVersion::Aes128(_, _) => 176,
            CipherVersion::Aes192(_, _) => 208,
        }
    }
    /// Returns the given key, as a vector.
    fn key(&self) -> Vec<u8> {
        match self {
            CipherVersion::Aes128(key, _) | CipherVersion::Aes192(key, _) => key.to_vec(),
        }
    }
    /// Returns the mode of operation used.
    fn mode_of_operation(&self) -> &ModeOfOperation {
        match self {
            CipherVersion::Aes128(_, mode) | CipherVersion::Aes192(_, mode) => mode,
        }
    }
}
impl Encryptable for &str {
    fn data(&self) -> Option<&[u8]> {
        if self.is_empty() {
            return None;
        };
        Some(self.as_bytes())
    }
}

impl Encryptable for &[u8] {
    fn data(&self) -> Option<&[u8]> {
        if self.len() < 1 {
            return None;
        }
        Some(*self)
    }
}

/// Additions the state and the round key as Galois fields GF(2^8) (XOR).
fn add_round_key(state: &mut [u8], round_key: &[u8]) {
    for i in 0..16 {
        state[i] = state[i] ^ round_key[i]; // Addition in Galois fields is defined as the addition MOD 2 which is XOR
    }
}
/// Applies PKCS#5 padding to blocks less than 16 bytes in length.
pub fn pkcs5_padding(block: &[u8]) -> Vec<u8> {
    let mut padded_block: Vec<u8> = Vec::new();
    padded_block.extend(block);
    for _ in 0..(16 - block.len()) {
        padded_block.push((16 - block.len()) as u8);
    }
    padded_block
}
/// Removes PKCS#5 padding from a decrypted sequence.
fn remove_pkcs5_padding(data: &mut Vec<u8>) {
    let padding_byte = data[data.len() - 1];
    if padding_byte >= 16 {
        // We can only pad up to 15 bytes, since we're dealing with words.
        return;
    }
    // Check if the padding is consistent.
    for i in data.len() - (padding_byte as usize)..data.len() {
        if data[i] != padding_byte {
            // Padding unconsistent. No padding was applied.
            return;
        }
    }
    data.drain(data.len() - (padding_byte as usize)..);
}
/// Encrypts a data object using the specified cipher version.
/// # Examples
/// Encrypting a text message in AES-128-ECB mode of operation.
/// ```
/// use plain_aes::{encrypt, ModeOfOperation, CipherVersion};
/// let message = "This is a super secret message";
/// let key = "This lib is cool";
/// let encrypted_message = encrypt(message, CipherVersion::Aes128(key.as_bytes(), ModeOfOperation::ECB)).unwrap();
/// let expected_enrypted: &[u8] = &[
///    0x11, 0x2B, 0xBD, 0x0D, 0x4C, 0x0C, 0xC5, 0x02, 0xB4, 0xC1, 0x38, 0xFD, 0x9A, 0x56,
///    0xC1, 0xA8, 0x78, 0x61, 0xD9, 0xF5, 0x6B, 0x48, 0xCC, 0xC5, 0x48, 0x14, 0xF2, 0x8C,
///    0x1A, 0x25, 0x11, 0xA3,
/// ];
/// assert!(expected_enrypted.iter().eq(encrypted_message.iter()))
/// ```
///
/// Encrypting a text message in AES-192-CBC mode of operation.
/// ```
/// use plain_aes::{encrypt, ModeOfOperation, CipherVersion};
/// let iv: [u8; 16] = [
///    0x54, 0x68, 0x69, 0x73, 0x20, 0x6C, 0x69, 0x62, 0x20, 0x69, 0x73, 0x20, 0x63, 0x6F,
///    0x6F, 0x6C,
/// ]; // You should not pass a fixed IV, this is for testing purposes.
/// let message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris ultricies egestas nunc luctus congue. Pellentesque in vehicula lectus. Maecenas facilisis in tellus non accumsan. Cras at nisl eros. Donec efficitur dolor vitae odio cursus semper. Nulla facilisi. Nunc sit amet congue tellus. Ut sollicitudin odio ac odio malesuada, in sodales turpis pharetra.";
/// let key = [0x54, 0x68, 0x69, 0x73, 0x20, 0x6C, 0x69, 0x62, 0x20, 0x63, 0x6F, 0x6F, 0x6C, 0x20, 0x79, 0x61, 0x64, 0x61, 0x20, 0x79, 0x61, 0x64, 0x61, 0x2E,]; // This lib cool yada yada.
/// let encrypted_message = encrypt(message, CipherVersion::Aes192(&key[..], ModeOfOperation::CBC(&iv))).unwrap();
/// let expected_enrypted: &[u8] = &[
///     0x65,0xB9,0x79,0x89,0xFE,0x5F,0x15,0xC3,0x0A,0x33,0xAF,0xAD,0xE7,0xA1,0x60,0x14,0x86,0x91,0x85,0x57,0x82,0x51,0xC2,0x15,0x24,0x52,0x69,0x16,0x69,0x11,0x54,0x42,0xFE,0x45,0x0A,0x5E,0x87,0xC7,0x30,0x74,0x93,0xBD,0x24,0x3F,0xBB,0x21,0xD7,0xC9,0x22,0xAB,0x7D,0x0C,0xEA,0x4B,0x26,0x3B,0x97,0x7D,0x52,0x19,0x56,0x14,0x02,0x7A,0x70,0x70,0xC7,0x2D,0x1A,0x99,0xA6,0x65,0x89,0x34,0x9F,0x84,0xE3,0xC6,0x8B,0x06,0x8B,0x6A,0x2F,0xD8,0x71,0xFC,0x25,0xAF,0x6C,0x56,0x76,0xB5,0xF2,0x5B,0xD5,0x09,0xD2,0xE4,0x53,0xDB,0x6A,0x81,0xFE,0x42,0x7D,0xB6,0x77,0x0E,0x72,0xCB,0x90,0xDD,0x89,0xCA,0xA5,0x66,0x18,0x20,0xD3,0xD3,0x2D,0x56,0xA9,0x8D,0x25,0x8D,0x30,0x4A,0x1D,0x09,0x6E,0x90,0xFC,0x02,0x0E,0x4F,0x0C,0x04,0x46,0x7F,0x34,0xA6,0x4C,0xAA,0x5B,0xD1,0x05,0x67,0x7A,0xC4,0x52,0x1A,0x1C,0x29,0x6D,0x21,0xF8,0x88,0x6B,0x70,0x55,0xC2,0x00,0x94,0x5E,0x78,0x8F,0x53,0x05,0x50,0xB6,0xDF,0x2D,0x38,0x4D,0x76,0x0D,0x4E,0xC4,0xCB,0x1F,0xBA,0x46,0x65,0x95,0xBE,0xDC,0x89,0x83,0x78,0x25,0x2F,0xA1,0xA6,0x53,0x8D,0xAB,0x61,0xB4,0xF3,0x2B,0x6B,0x72,0x03,0xD7,0x54,0xFF,0xCB,0xA6,0xA1,0x26,0x97,0x84,0x43,0x26,0x49,0xDC,0x3E,0x14,0xCC,0x99,0x8F,0x30,0xE7,0xF6,0x11,0x40,0x87,0x9F,0xB2,0x65,0x40,0xB0,0x96,0x3D,0x6A,0x9D,0x89,0xC1,0x0F,0x25,0x4B,0x9F,0x26,0x5A,0x9F,0x52,0xC9,0x8D,0x72,0xE6,0x1F,0x0F,0xB8,0x2D,0x4F,0xA1,0x9F,0x29,0xEE,0xD2,0x61,0x61,0x6A,0x03,0xDF,0x33,0xB4,0xE8,0xA8,0x6F,0x73,0x87,0xAD,0xB4,0x93,0xB6,0xFA,0x76,0xCA,0x5C,0x38,0x01,0x0D,0x2B,0xC1,0x18,0xF5,0x4D,0x0F,0x84,0x08,0x94,0xCB,0xBE,0x91,0x7B,0x3D,0x5A,0xCD,0xE4,0x92,0x2B,0xD3,0xF4,0x02,0xB5,0x1B,0xEC,0x68,0xFB,0x72,0xAA,0x62,0x6B,0xA0,0xD2,0xF7,0xAB,0xF1,0x2E,0xCC,0xFB,0x38,0xBC,0xE0,0x83,0xB1,0x70,0xA5,0x94,0xF4,0xB3,0x92,0x2D,0x94,0xD2,0x5C,0x24,0x38,0x31,0xAB,0x59,0x29,0xE5,0x7A,0x98,0xF3,0x60,0x24,0x45,0xAD,0x55,0x57,0x5F,0x24,0x99,0xC0,0xD9,0x11,0xE1,0xEB,0x4C,0xDB,0xA4,0xCE,0x82,0xC2,
/// ];
/// assert!(expected_enrypted.iter().eq(encrypted_message.iter()))
/// ```

pub fn encrypt<T>(target: T, cipher_version: CipherVersion) -> Result<Vec<u8>, OperationError>
where
    T: Encryptable,
{
    match cipher_version.mode_of_operation() {
        ModeOfOperation::CBC(iv) => {
            match target.data() {
                None => Err(OperationError::EmptyTarget),
                Some(data) => {
                    if data.len() < 16 {
                        return Err(OperationError::InvalidTargetSize);
                    }
                    let mut cipher_data: Vec<u8> = Vec::new();
                    let key_expansion = ExpandedKey::new(&cipher_version);
                    if key_expansion.is_err() {
                        return Err(OperationError::KeyExpansionFailed(
                            key_expansion.unwrap_err(),
                        ));
                    }
                    let expanded_key = key_expansion.unwrap();

                    let block_num = data.len() / 16;
                    let mut previous_encrypted_block: Option<[u8; 16]> = None;
                    for i in 0..block_num {
                        let block = &data[i * 16..(i + 1) * 16];
                        let mut copied_block = block.to_vec(); // We must copy the current block because the initial data is not mutable, meaning the block cannot be mutated.
                        let cipher_slice = copied_block.as_mut_slice();
                        if let None = previous_encrypted_block {
                            add_round_key(cipher_slice, *iv);
                        } else {
                            add_round_key(cipher_slice, &previous_encrypted_block.unwrap());
                        }
                        let encrypted_block = encrypt_block(cipher_slice, &expanded_key);
                        previous_encrypted_block = Some(encrypted_block);
                        cipher_data.extend(encrypted_block);
                    }
                    if data.len() % 16 != 0 {
                        // There is remaining bytes less than 16 in length.
                        let mut padded_vec = pkcs5_padding(&data[(block_num * 16)..]);
                        let padded_block = padded_vec.as_mut_slice();
                        add_round_key(padded_block, &previous_encrypted_block.unwrap());
                        cipher_data.extend(encrypt_block(padded_block, &expanded_key));
                    }
                    Ok(cipher_data)
                }
            }
        }
        ModeOfOperation::ECB => match target.data() {
            None => Err(OperationError::EmptyTarget),
            Some(data) => {
                if data.len() < 16 {
                    return Err(OperationError::InvalidTargetSize);
                }
                let mut cipher_data: Vec<u8> = Vec::new();
                let key_expansion = ExpandedKey::new(&cipher_version);
                if key_expansion.is_err() {
                    return Err(OperationError::KeyExpansionFailed(
                        key_expansion.unwrap_err(),
                    ));
                }
                let expanded_key = key_expansion.unwrap();

                let block_num = data.len() / 16;
                for i in 0..block_num {
                    let block = &data[i * 16..(i + 1) * 16];
                    let encrypted_block = encrypt_block(&block, &expanded_key);
                    cipher_data.extend(encrypted_block);
                }
                if data.len() % 16 != 0 {
                    // There is remaining bytes less than 16 in length.
                    let padded_block = pkcs5_padding(&data[(block_num * 16)..]);
                    cipher_data.extend(encrypt_block(&padded_block[..], &expanded_key));
                }
                Ok(cipher_data)
            }
        },
    }
}
/// Decrypts a data object using the specified cipher version.
/// # Examples
/// Decrypting a byte sequence encrypted in AES-192-CBC mode of operation.
/// ```
/// use plain_aes::{decrypt, ModeOfOperation, CipherVersion};
/// let iv: [u8; 16] = [
///    0x54, 0x68, 0x69, 0x73, 0x20, 0x6C, 0x69, 0x62, 0x20, 0x69, 0x73, 0x20, 0x63, 0x6F,
///    0x6F, 0x6C,
/// ]; // You should not pass a fixed IV, this is for testing purposes.
/// let message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris ultricies egestas nunc luctus congue. Pellentesque in vehicula lectus. Maecenas facilisis in tellus non accumsan. Cras at nisl eros. Donec efficitur dolor vitae odio cursus semper. Nulla facilisi. Nunc sit amet congue tellus. Ut sollicitudin odio ac odio malesuada, in sodales turpis pharetra.";
/// let key = [0x54, 0x68, 0x69, 0x73, 0x20, 0x6C, 0x69, 0x62, 0x20, 0x63, 0x6F, 0x6F, 0x6C, 0x20, 0x79, 0x61, 0x64, 0x61, 0x20, 0x79, 0x61, 0x64, 0x61, 0x2E,]; // This lib cool yada yada.
/// let encrypted: &[u8] = &[
///     0x65,0xB9,0x79,0x89,0xFE,0x5F,0x15,0xC3,0x0A,0x33,0xAF,0xAD,0xE7,0xA1,0x60,0x14,0x86,0x91,0x85,0x57,0x82,0x51,0xC2,0x15,0x24,0x52,0x69,0x16,0x69,0x11,0x54,0x42,0xFE,0x45,0x0A,0x5E,0x87,0xC7,0x30,0x74,0x93,0xBD,0x24,0x3F,0xBB,0x21,0xD7,0xC9,0x22,0xAB,0x7D,0x0C,0xEA,0x4B,0x26,0x3B,0x97,0x7D,0x52,0x19,0x56,0x14,0x02,0x7A,0x70,0x70,0xC7,0x2D,0x1A,0x99,0xA6,0x65,0x89,0x34,0x9F,0x84,0xE3,0xC6,0x8B,0x06,0x8B,0x6A,0x2F,0xD8,0x71,0xFC,0x25,0xAF,0x6C,0x56,0x76,0xB5,0xF2,0x5B,0xD5,0x09,0xD2,0xE4,0x53,0xDB,0x6A,0x81,0xFE,0x42,0x7D,0xB6,0x77,0x0E,0x72,0xCB,0x90,0xDD,0x89,0xCA,0xA5,0x66,0x18,0x20,0xD3,0xD3,0x2D,0x56,0xA9,0x8D,0x25,0x8D,0x30,0x4A,0x1D,0x09,0x6E,0x90,0xFC,0x02,0x0E,0x4F,0x0C,0x04,0x46,0x7F,0x34,0xA6,0x4C,0xAA,0x5B,0xD1,0x05,0x67,0x7A,0xC4,0x52,0x1A,0x1C,0x29,0x6D,0x21,0xF8,0x88,0x6B,0x70,0x55,0xC2,0x00,0x94,0x5E,0x78,0x8F,0x53,0x05,0x50,0xB6,0xDF,0x2D,0x38,0x4D,0x76,0x0D,0x4E,0xC4,0xCB,0x1F,0xBA,0x46,0x65,0x95,0xBE,0xDC,0x89,0x83,0x78,0x25,0x2F,0xA1,0xA6,0x53,0x8D,0xAB,0x61,0xB4,0xF3,0x2B,0x6B,0x72,0x03,0xD7,0x54,0xFF,0xCB,0xA6,0xA1,0x26,0x97,0x84,0x43,0x26,0x49,0xDC,0x3E,0x14,0xCC,0x99,0x8F,0x30,0xE7,0xF6,0x11,0x40,0x87,0x9F,0xB2,0x65,0x40,0xB0,0x96,0x3D,0x6A,0x9D,0x89,0xC1,0x0F,0x25,0x4B,0x9F,0x26,0x5A,0x9F,0x52,0xC9,0x8D,0x72,0xE6,0x1F,0x0F,0xB8,0x2D,0x4F,0xA1,0x9F,0x29,0xEE,0xD2,0x61,0x61,0x6A,0x03,0xDF,0x33,0xB4,0xE8,0xA8,0x6F,0x73,0x87,0xAD,0xB4,0x93,0xB6,0xFA,0x76,0xCA,0x5C,0x38,0x01,0x0D,0x2B,0xC1,0x18,0xF5,0x4D,0x0F,0x84,0x08,0x94,0xCB,0xBE,0x91,0x7B,0x3D,0x5A,0xCD,0xE4,0x92,0x2B,0xD3,0xF4,0x02,0xB5,0x1B,0xEC,0x68,0xFB,0x72,0xAA,0x62,0x6B,0xA0,0xD2,0xF7,0xAB,0xF1,0x2E,0xCC,0xFB,0x38,0xBC,0xE0,0x83,0xB1,0x70,0xA5,0x94,0xF4,0xB3,0x92,0x2D,0x94,0xD2,0x5C,0x24,0x38,0x31,0xAB,0x59,0x29,0xE5,0x7A,0x98,0xF3,0x60,0x24,0x45,0xAD,0x55,0x57,0x5F,0x24,0x99,0xC0,0xD9,0x11,0xE1,0xEB,0x4C,0xDB,0xA4,0xCE,0x82,0xC2,
/// ];
/// let decrypted_message = decrypt(encrypted, CipherVersion::Aes192(&key[..], ModeOfOperation::CBC(&iv))).unwrap();
/// let expected_decrypted = message.as_bytes();
/// assert!(expected_decrypted.iter().eq(decrypted_message.iter()))
/// ```
/// Decrypting a byte sequence encrypted in AES-128-ECB mode of operation.
/// ```
/// use plain_aes::{decrypt, ModeOfOperation, CipherVersion};
/// let key = [
///    0x54, 0x68, 0x69, 0x73, 0x20, 0x6C, 0x69, 0x62, 0x20, 0x69, 0x73, 0x20, 0x63, 0x6F,
///    0x6F, 0x6C,
/// ]; // This lib is cool
/// let message = "This is a super secret message";
/// let encrypted: &[u8] = &[
///    0x11, 0x2B, 0xBD, 0x0D, 0x4C, 0x0C, 0xC5, 0x02, 0xB4, 0xC1, 0x38, 0xFD, 0x9A, 0x56,
///    0xC1, 0xA8, 0x78, 0x61, 0xD9, 0xF5, 0x6B, 0x48, 0xCC, 0xC5, 0x48, 0x14, 0xF2, 0x8C,
///    0x1A, 0x25, 0x11, 0xA3,
/// ];
/// let decrypted_message = decrypt(encrypted, CipherVersion::Aes128(&key[..], ModeOfOperation::ECB)).unwrap();
/// let expected_decrypted = message.as_bytes();
/// assert!(expected_decrypted.iter().eq(decrypted_message.iter()))
/// ```
pub fn decrypt<T>(target: T, cipher_version: CipherVersion) -> Result<Vec<u8>, OperationError>
where
    T: Encryptable,
{
    match cipher_version.mode_of_operation() {
        ModeOfOperation::CBC(iv) => match target.data() {
            None => Err(OperationError::EmptyTarget),
            Some(data) => {
                if data.len() < 16 {
                    return Err(OperationError::InvalidTargetSize);
                }
                let mut plain_data: Vec<u8> = Vec::new();
                let key_expansion = ExpandedKey::new(&cipher_version);
                if key_expansion.is_err() {
                    return Err(OperationError::KeyExpansionFailed(
                        key_expansion.unwrap_err(),
                    ));
                }
                let expanded_key = key_expansion.unwrap();
                let block_num: usize = data.len() / 16;
                let mut previous_encrypted_block: Option<[u8; 16]> = None;
                for i in 0..block_num {
                    let block = &data[i * 16..(i + 1) * 16];
                    let mut decrypted_block = decrypt_block(block, &expanded_key);
                    if let None = previous_encrypted_block {
                        add_round_key(&mut decrypted_block[..], *iv);
                    } else {
                        add_round_key(&mut decrypted_block[..], &previous_encrypted_block.unwrap());
                    }
                    let mut fixed_block: [u8; 16] = [0; 16];
                    for i in 0..16 {
                        fixed_block[i] = block[i];
                    }
                    previous_encrypted_block = Some(fixed_block);
                    plain_data.extend(decrypted_block);
                }
                remove_pkcs5_padding(&mut plain_data);
                Ok(plain_data)
            }
        },
        ModeOfOperation::ECB => match target.data() {
            None => Err(OperationError::EmptyTarget),
            Some(data) => {
                if data.len() < 16 {
                    return Err(OperationError::InvalidTargetSize);
                }
                let mut plain_data: Vec<u8> = Vec::new();
                let key_expansion = ExpandedKey::new(&cipher_version);
                if key_expansion.is_err() {
                    return Err(OperationError::KeyExpansionFailed(
                        key_expansion.unwrap_err(),
                    ));
                }
                let expanded_key = key_expansion.unwrap();
                let block_num = data.len() / 16;
                for i in 0..block_num {
                    let block = &data[i * 16..(i + 1) * 16];
                    let decrypted_block = decrypt_block(block, &expanded_key);
                    plain_data.extend(decrypted_block);
                }
                // TO DO, alert user if data size is not 128 bits compliant (a block less than 16 bytes in size is left).
                remove_pkcs5_padding(&mut plain_data);
                Ok(plain_data)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs5_padding_test() {
        let block = [0x68, 0xe4, 0x48, 0xd5, 0xa9, 0xa4];
        let expected_padded_block = [
            0x68, 0xe4, 0x48, 0xd5, 0xa9, 0xa4, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
            0x0a, 0x0a,
        ];
        let padded_block = pkcs5_padding(&block);
        assert!(expected_padded_block.iter().eq(padded_block.iter()));
    }
    #[test]
    fn remove_pkcs5_padding_test() {
        let mut block = vec![
            0x68, 0xe4, 0x48, 0xd5, 0xa9, 0xa4, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
            0x0a, 0x0a,
        ];
        let expected_clean_block = [0x68, 0xe4, 0x48, 0xd5, 0xa9, 0xa4];
        remove_pkcs5_padding(&mut block);
        assert!(expected_clean_block.iter().eq(block.iter()));
    }
    #[test]
    fn remove_pkcs5_padding_unconsistent_test() {
        let mut block = vec![
            0x68, 0xe4, 0x48, 0xd5, 0xa9, 0xa4, 0x68, 0xe4, 0x48, 0xd5, 0xa9, 0xa4, 0x6d, 0x0a,
            0x0a, 0x0a,
        ]; // We have what appears to be PKCS#5 padding, but unconsistent, should not mutate the block.
        let original_block = block.clone();
        remove_pkcs5_padding(&mut block);
        assert!(original_block.iter().eq(block.iter()));
    }
}
