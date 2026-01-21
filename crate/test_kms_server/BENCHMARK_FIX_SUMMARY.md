# 基准测试修复总结

## 问题描述

运行 `cargo bench` 时，基准测试在 `Symmetric encryption/AES 128 GCM 128bit encryption` 阶段失败，错误信息为：

```
thread 'main' panicked at crate/test_kms_server/benches/symmetric_benches.rs:210:18:
called `Result::unwrap()` on an `Err` value: RequestFailed("/kmip/2_1: Item_Not_Found: Encrypt: no valid key for id: 21626978-dac2-42a2-b045-c3c2df1d8e23")
```

## 根本原因

在 `crate/test_kms_server/benches/symmetric_benches.rs` 中，`create_symmetric_key_request` 函数创建对称密钥时，没有设置 `activation_date` 字段。根据 KMIP 规范，没有激活日期的密钥默认处于 "PreActive" 状态，不能立即用于加密操作。

对比 `crate/test_kms_server/src/test_server.rs` 中的 `create_kek_in_db` 函数（第 488 行），发现它明确设置了 `activation_date: Some(time_normalize()?)` 来确保密钥立即激活并可用。

## 解决方案

修改 `crate/test_kms_server/benches/symmetric_benches.rs` 文件：

### 1. 添加必要的导入

在文件开头添加 `time_normalize` 函数的导入：

```rust
use cosmian_kms_client::{
    KmsClient, KmsClientError,
    cosmian_kmip::time_normalize,  // 新增这一行
    kmip_0::kmip_types::{BlockCipherMode, CryptographicUsageMask},
    kmip_2_1::{
        extra::BulkData,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Decrypt, Encrypt},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, KeyFormatType, UniqueIdentifier,
        },
    },
};
```

### 2. 修改密钥创建函数

在 `create_symmetric_key_request` 函数中添加 `activation_date` 字段（第 118 行）：

```rust
fn create_symmetric_key_request<T: IntoIterator<Item = impl AsRef<str>>>(
    num_bits: i32,
    cryptographic_parameters: CryptographicParameters,
    tags: T,
) -> Result<Create, KmsClientError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(
            cryptographic_parameters
                .cryptographic_algorithm
                .unwrap_or(CryptographicAlgorithm::AES),
        ),
        cryptographic_length: Some(num_bits),
        cryptographic_parameters: Some(cryptographic_parameters),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        activation_date: Some(time_normalize()?),  // 新增这一行
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;
    Ok(Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    })
}
```

## 验证结果

修复后运行 `cargo bench`，所有基准测试成功通过：

- ✅ Symmetric key tests/AES 128bit key creation
- ✅ Symmetric key tests/AES 256bit key creation
- ✅ Symmetric encryption/AES 128 GCM 128bit encryption of 1 plaintext(s)
- ✅ Symmetric encryption/AES 256 GCM 256bit encryption of 1 plaintext(s)
- ✅ Symmetric encryption/AES GCM 128bit decryption of 1 ciphertext(s)
- ✅ Symmetric encryption/AES GCM 256bit decryption of 1 ciphertext(s)
- ✅ Symmetric encryption/AES 256 GCM 256bit encryption of 100000 plaintext(s)
- ✅ Symmetric encryption/AES GCM 256bit decryption of 100000 ciphertext(s)
- ✅ RSA tests (all variants)

## 修改文件

- `crate/test_kms_server/benches/symmetric_benches.rs`

## 技术说明

`time_normalize()` 函数返回当前时间的标准化版本，用作密钥的激活日期。设置此字段确保密钥在创建后立即处于 "Active" 状态，可以用于加密操作。

这个修复与 KMS 服务器中创建 KEK（Key Encryption Key）的方式保持一致，确保了测试环境中密钥创建的正确性。
