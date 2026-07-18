#![allow(clippy::print_stdout)]

use std::{
    collections::HashMap,
    env,
    error::Error,
    time::{Duration, Instant},
};

use cosmian_kms_interfaces::{
    CryptoAlgorithm, EncryptedContent, HSM, HsmKeyAlgorithm, HsmKeypairAlgorithm,
};
use futures::executor::block_on;
use softhsm2_pkcs11_loader::{SOFTHSM2_PKCS11_LIB, Softhsm2};

fn fill_bytes(buffer: &mut [u8], seed: u8) {
    let mut state = seed;
    for byte in buffer.iter_mut() {
        state = state.wrapping_mul(131).wrapping_add(17);
        *byte = state;
    }
}

fn aes_iterations_for(message_bytes: usize) -> u32 {
    let target = 8_usize * 1024 * 1024;
    let mut iterations = if message_bytes == 0 {
        1
    } else {
        target / message_bytes
    };
    iterations = iterations.clamp(2, 100);
    u32::try_from(iterations).unwrap_or(100)
}

fn rsa_iterations_for(operation: &str) -> u32 {
    if operation.contains("verify") || operation.contains("encrypt") {
        128
    } else {
        32
    }
}

fn print_result(
    backend: &str,
    operation: &str,
    bytes_or_bits: usize,
    iterations: u32,
    elapsed: Duration,
) {
    let seconds = elapsed.as_secs_f64();
    let ops = f64::from(iterations);
    let gbps = if operation.starts_with("aes-") {
        ops * bytes_or_bits as f64 * 8.0 / seconds / 1.0e9
    } else {
        0.0
    };
    println!(
        "base_hsm,{backend},{operation},{bytes_or_bits},1,{iterations},{seconds:.9},{ops_s:.3},{gbps:.6}",
        ops_s = ops / seconds
    );
}

fn pack_gcm(content: &EncryptedContent) -> Result<Vec<u8>, Box<dyn Error>> {
    let iv = content
        .iv
        .as_ref()
        .ok_or("AES-GCM encrypted content is missing IV")?;
    let tag = content
        .tag
        .as_ref()
        .ok_or("AES-GCM encrypted content is missing tag")?;
    let mut packed = Vec::with_capacity(iv.len() + content.ciphertext.len() + tag.len());
    packed.extend_from_slice(iv);
    packed.extend_from_slice(&content.ciphertext);
    packed.extend_from_slice(tag);
    Ok(packed)
}

async fn benchmark_aes_gcm(
    hsm: &Softhsm2,
    slot_id: usize,
    key_id: &[u8],
    backend: &str,
    message_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    let mut plaintext = vec![0_u8; message_bytes];
    let mut aad = vec![0_u8; 20];
    fill_bytes(&mut plaintext, 17);
    fill_bytes(&mut aad, 0xa0);

    let encrypted = hsm
        .encrypt(slot_id, key_id, CryptoAlgorithm::AesGcm, &plaintext, &aad)
        .await?;
    let packed = pack_gcm(&encrypted)?;
    let recovered = hsm
        .decrypt(slot_id, key_id, CryptoAlgorithm::AesGcm, &packed, &aad)
        .await?;
    if recovered.as_slice() != plaintext.as_slice() {
        return Err("AES-GCM warmup roundtrip mismatch".into());
    }

    let iterations = aes_iterations_for(message_bytes);
    let start = Instant::now();
    let mut last_encrypted = encrypted;
    for _ in 0..iterations {
        last_encrypted = hsm
            .encrypt(slot_id, key_id, CryptoAlgorithm::AesGcm, &plaintext, &aad)
            .await?;
    }
    print_result(
        backend,
        "aes-256-gcm-encrypt",
        message_bytes,
        iterations,
        start.elapsed(),
    );

    let packed = pack_gcm(&last_encrypted)?;
    let start = Instant::now();
    for _ in 0..iterations {
        drop(
            hsm.decrypt(slot_id, key_id, CryptoAlgorithm::AesGcm, &packed, &aad)
                .await?,
        );
    }
    print_result(
        backend,
        "aes-256-gcm-decrypt",
        message_bytes,
        iterations,
        start.elapsed(),
    );
    Ok(())
}

async fn benchmark_rsa_encrypt_decrypt(
    hsm: &Softhsm2,
    slot_id: usize,
    public_key_id: &[u8],
    private_key_id: &[u8],
    backend: &str,
) -> Result<(), Box<dyn Error>> {
    let mut message = vec![0_u8; 48];
    fill_bytes(&mut message, 0x31);
    let encrypted = hsm
        .encrypt(
            slot_id,
            public_key_id,
            CryptoAlgorithm::RsaOaepSha256,
            &message,
            &[],
        )
        .await?;
    let recovered = hsm
        .decrypt(
            slot_id,
            private_key_id,
            CryptoAlgorithm::RsaOaepSha256,
            &encrypted.ciphertext,
            &[],
        )
        .await?;
    if recovered.as_slice() != message.as_slice() {
        return Err("RSA-OAEP-SHA256 warmup roundtrip mismatch".into());
    }

    let iterations = rsa_iterations_for("rsa-2048-oaep-sha256-encrypt");
    let start = Instant::now();
    let mut last_ciphertext = encrypted.ciphertext;
    for _ in 0..iterations {
        last_ciphertext = hsm
            .encrypt(
                slot_id,
                public_key_id,
                CryptoAlgorithm::RsaOaepSha256,
                &message,
                &[],
            )
            .await?
            .ciphertext;
    }
    print_result(
        backend,
        "rsa-2048-oaep-sha256-encrypt",
        2048,
        iterations,
        start.elapsed(),
    );

    let iterations = rsa_iterations_for("rsa-2048-oaep-sha256-decrypt");
    let start = Instant::now();
    for _ in 0..iterations {
        drop(
            hsm.decrypt(
                slot_id,
                private_key_id,
                CryptoAlgorithm::RsaOaepSha256,
                &last_ciphertext,
                &[],
            )
            .await?,
        );
    }
    print_result(
        backend,
        "rsa-2048-oaep-sha256-decrypt",
        2048,
        iterations,
        start.elapsed(),
    );
    Ok(())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let backend = env::args().nth(1).unwrap_or_else(|| "unknown".to_owned());
    let lib_path =
        env::var("SOFTHSM2_PKCS11_LIB").unwrap_or_else(|_| SOFTHSM2_PKCS11_LIB.to_owned());
    let slot_id: usize = env::var("HSM_SLOT_ID")?.parse()?;
    let password = env::var("HSM_USER_PASSWORD")?;
    let hsm = Softhsm2::instantiate(&lib_path, HashMap::from([(slot_id, Some(password))]))?;

    let process_id = std::process::id();
    let aes_id = format!("bench-aes-{backend}-{process_id}");
    let rsa_sk_id = format!("bench-rsa-sk-{backend}-{process_id}");
    let rsa_pk_id = format!("bench-rsa-pk-{backend}-{process_id}");

    hsm.create_key(slot_id, aes_id.as_bytes(), HsmKeyAlgorithm::AES, 256, true)
        .await?;
    hsm.create_keypair(
        slot_id,
        rsa_sk_id.as_bytes(),
        rsa_pk_id.as_bytes(),
        HsmKeypairAlgorithm::RSA,
        2048,
        true,
    )
    .await?;

    for message_bytes in [64_usize, 65_536, 1_048_576] {
        benchmark_aes_gcm(&hsm, slot_id, aes_id.as_bytes(), &backend, message_bytes).await?;
    }
    benchmark_rsa_encrypt_decrypt(
        &hsm,
        slot_id,
        rsa_pk_id.as_bytes(),
        rsa_sk_id.as_bytes(),
        &backend,
    )
    .await?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    block_on(run())
}
