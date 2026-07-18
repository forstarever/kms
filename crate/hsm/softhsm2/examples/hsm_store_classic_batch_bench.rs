#![allow(clippy::print_stdout)]

use std::{
    collections::HashMap,
    env,
    error::Error,
    sync::Arc,
    time::{Duration, Instant},
};

use cosmian_kms_interfaces::{
    CryptoAlgorithm, CryptoDecryptBatchRequest, CryptoEncryptBatchRequest, CryptoOracle, HSM,
    HsmKeypairAlgorithm, HsmStore,
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

fn parse_usize_values(name: &str, default_values: &[usize]) -> Result<Vec<usize>, Box<dyn Error>> {
    let raw = env::var(name).unwrap_or_else(|_| {
        default_values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    });
    let values = raw
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<usize>, _>>()?;
    if values.is_empty() {
        return Err(format!("{name} did not contain any values").into());
    }
    Ok(values)
}

fn iterations_for_batch(batch: usize, operation: &str) -> usize {
    let target_ops = if operation.contains("encrypt") {
        512_usize
    } else {
        128_usize
    };
    (target_ops / batch.max(1)).clamp(2, 128)
}

fn print_result(
    backend: &str,
    operation: &str,
    key_bits: usize,
    batch: usize,
    iterations: usize,
    elapsed: Duration,
) {
    let seconds = elapsed.as_secs_f64();
    let total_ops = batch * iterations;
    println!(
        "hsm_store_batch,{backend},{operation},{key_bits},{batch},{iterations},{total_ops},{seconds:.9},{ops_s:.3},{avg_ms:.3}",
        ops_s = total_ops as f64 / seconds,
        avg_ms = seconds * 1_000.0 / total_ops as f64,
    );
}

async fn benchmark_rsa_oaep_batch(
    store: &HsmStore,
    public_uid: &str,
    private_uid: &str,
    backend: &str,
    key_bits: usize,
    batch_values: &[usize],
) -> Result<(), Box<dyn Error>> {
    let mut message = vec![0_u8; 48];
    fill_bytes(&mut message, 0x31);
    let warmup = store
        .encrypt(
            public_uid,
            &message,
            Some(CryptoAlgorithm::RsaOaepSha256),
            None,
        )
        .await?;
    let recovered = store
        .decrypt(
            private_uid,
            &warmup.ciphertext,
            Some(CryptoAlgorithm::RsaOaepSha256),
            None,
        )
        .await?;
    if recovered.as_slice() != message.as_slice() {
        return Err("HsmStore batch RSA-OAEP-SHA256 warmup roundtrip mismatch".into());
    }

    for &batch in batch_values {
        let encrypt_requests = (0..batch)
            .map(|_| CryptoEncryptBatchRequest {
                uid: public_uid.to_owned(),
                data: message.clone(),
                cryptographic_algorithm: Some(CryptoAlgorithm::RsaOaepSha256),
                authenticated_encryption_additional_data: None,
            })
            .collect::<Vec<_>>();
        let iterations = iterations_for_batch(batch, "encrypt");
        let start = Instant::now();
        let mut encrypted = Vec::new();
        for _ in 0..iterations {
            encrypted = store.encrypt_batch(&encrypt_requests).await?;
        }
        print_result(
            backend,
            &format!("rsa-{key_bits}-oaep-sha256-encrypt"),
            key_bits,
            batch,
            iterations,
            start.elapsed(),
        );

        let decrypt_requests = encrypted
            .into_iter()
            .map(|content| CryptoDecryptBatchRequest {
                uid: private_uid.to_owned(),
                data: content.ciphertext,
                cryptographic_algorithm: Some(CryptoAlgorithm::RsaOaepSha256),
                authenticated_encryption_additional_data: None,
            })
            .collect::<Vec<_>>();
        let iterations = iterations_for_batch(batch, "decrypt");
        let start = Instant::now();
        for _ in 0..iterations {
            let recovered = store.decrypt_batch(&decrypt_requests).await?;
            for plaintext in recovered {
                if plaintext.as_slice() != message.as_slice() {
                    return Err("HsmStore batch RSA-OAEP-SHA256 decrypt mismatch".into());
                }
            }
        }
        print_result(
            backend,
            &format!("rsa-{key_bits}-oaep-sha256-decrypt"),
            key_bits,
            batch,
            iterations,
            start.elapsed(),
        );
    }
    Ok(())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let backend = env::args().nth(1).unwrap_or_else(|| "unknown".to_owned());
    let rsa_bits: usize = env::var("SOFTHSM_CLASSIC_BENCH_RSA_BITS")
        .unwrap_or_else(|_| "2048".to_owned())
        .parse()?;
    if !matches!(rsa_bits, 2048 | 3072 | 4096) {
        return Err(format!("unsupported SOFTHSM_CLASSIC_BENCH_RSA_BITS value: {rsa_bits}").into());
    }
    let batch_values = parse_usize_values("SOFTHSM_CLASSIC_BATCH_VALUES", &[1, 8, 32, 64])?;
    let lib_path =
        env::var("SOFTHSM2_PKCS11_LIB").unwrap_or_else(|_| SOFTHSM2_PKCS11_LIB.to_owned());
    let slot_id: usize = env::var("HSM_SLOT_ID")?.parse()?;
    let password = env::var("HSM_USER_PASSWORD")?;
    let hsm = Arc::new(Softhsm2::instantiate(
        &lib_path,
        HashMap::from([(slot_id, Some(password))]),
    )?);

    let process_id = std::process::id();
    let rsa_sk_id = format!("bench-store-batch-rsa{rsa_bits}-sk-{backend}-{process_id}");
    let rsa_pk_id = format!("bench-store-batch-rsa{rsa_bits}-pk-{backend}-{process_id}");
    hsm.create_keypair(
        slot_id,
        rsa_sk_id.as_bytes(),
        rsa_pk_id.as_bytes(),
        HsmKeypairAlgorithm::RSA,
        rsa_bits,
        true,
    )
    .await?;

    let store = HsmStore::new(hsm, &["*".to_owned()], "softhsm2", "hsm");
    let rsa_sk_uid = format!("hsm::{slot_id}::{rsa_sk_id}");
    let rsa_pk_uid = format!("hsm::{slot_id}::{rsa_pk_id}");
    benchmark_rsa_oaep_batch(
        &store,
        &rsa_pk_uid,
        &rsa_sk_uid,
        &backend,
        rsa_bits,
        &batch_values,
    )
    .await
}

fn main() -> Result<(), Box<dyn Error>> {
    block_on(run())
}
