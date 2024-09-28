use plain_aes::{encrypt, CipherVersion, KeyExpansionError, ModeOfOperation, OperationError};

#[test]
fn encrypt_aes128_cbc_u8_block_1() {
    let key: &[u8] = &[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let iv: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let plain: &[u8] = &[
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    let cipher: &[u8] = &[
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19,
        0x7d,
    ];
    let result = encrypt(plain, CipherVersion::Aes128(key, ModeOfOperation::CBC(iv)));
    assert!(cipher.iter().eq(result.unwrap().iter()))
}
#[test]
fn encrypt_aes128_cbc_u8_block_2() {
    let key: &[u8] = &[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let iv: &[u8] = &[
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D,
    ];
    let plain: &[u8] = &[
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e,
        0x51,
    ];
    let cipher: &[u8] = &[
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78,
        0xb2,
    ];
    let result = encrypt(plain, CipherVersion::Aes128(key, ModeOfOperation::CBC(iv)));
    assert!(cipher.iter().eq(result.unwrap().iter()))
}
#[test]
fn encrypt_aes128_cbc_u8_block_3() {
    let key: &[u8] = &[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let iv: &[u8] = &[
        0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78,
        0xB2,
    ];
    let plain: &[u8] = &[
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52,
        0xef,
    ];
    let cipher: &[u8] = &[
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95,
        0x16,
    ];
    let result = encrypt(plain, CipherVersion::Aes128(key, ModeOfOperation::CBC(iv)));
    assert!(cipher.iter().eq(result.unwrap().iter()))
}
#[test]
fn encrypt_aes128_cbc_u8_block_4() {
    let key: &[u8] = &[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let iv: &[u8] = &[
        0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95,
        0x16,
    ];
    let plain: &[u8] = &[
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37,
        0x10,
    ];
    let cipher: &[u8] = &[
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1,
        0xa7,
    ];
    let result = encrypt(plain, CipherVersion::Aes128(key, ModeOfOperation::CBC(iv)));
    assert!(cipher.iter().eq(result.unwrap().iter()))
}
#[test]
fn encrypt_aes128_cbc_empty_string_empty_u8() {
    let plain = "".as_bytes(); // Empty slice.
    let plain2 = ""; // Empty string
    let key: &[u8] = &[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let iv: &[u8] = &[
        0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95,
        0x16,
    ];
    let result = encrypt(plain, CipherVersion::Aes128(key, ModeOfOperation::CBC(iv)));
    let result2 = encrypt(plain2, CipherVersion::Aes128(key, ModeOfOperation::CBC(iv)));
    assert_eq!(result.unwrap_err(), OperationError::EmptyTarget);
    assert_eq!(result2.unwrap_err(), OperationError::EmptyTarget);
}

#[test]
fn encrypt_aes128_cbc_key_expansion_failure() {
    let key = [
        0x54, 0x68, 0x69, 0x73, 0x20, 0x6C, 0x69, 0x62, 0x20, 0x69, 0x73, 0x20, 0x63, 0x6F,
    ]; // Key's length is invalid for AES-128
    let plain = "This is a test plain.";
    let iv: &[u8] = &[
        0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95,
        0x16,
    ];
    let result = encrypt(plain, CipherVersion::Aes128(&key, ModeOfOperation::CBC(iv)));
    assert_eq!(
        result.unwrap_err(),
        OperationError::KeyExpansionFailed(KeyExpansionError::InvalidKeyLength {
            expected: 16,
            actual: 14
        })
    )
}
#[test]
fn encrypt_aes128_cbc_invalid_target_size() {
    let key: &[u8] = &[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let iv: &[u8] = &[
        0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95,
        0x16,
    ];
    let plain = "abc";
    let result = encrypt(plain, CipherVersion::Aes128(key, ModeOfOperation::CBC(iv)));
    assert_eq!(result.unwrap_err(), OperationError::InvalidTargetSize);
}