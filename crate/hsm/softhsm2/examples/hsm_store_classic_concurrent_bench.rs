#![allow(clippy::print_stdout)]

use std::{
    collections::HashMap,
    env,
    error::Error,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use cosmian_kms_interfaces::{
    CryptoOracle, EncryptedContent, HSM, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmStore,
};
use futures::executor::block_on;
use softhsm2_pkcs11_loader::{SOFTHSM2_PKCS11_LIB, Softhsm2};

enum WorkerCommand {
    Run,
    Stop,
}

struct WaveStats {
    total_ops: usize,
    elapsed: Duration,
    latencies: Vec<Duration>,
}

fn fill_bytes(buffer: &mut [u8], seed: u8) {
    let mut state = seed;
    for byte in buffer.iter_mut() {
        state = state.wrapping_mul(131).wrapping_add(17);
        *byte = state;
    }
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

fn run_threaded_waves<F>(
    concurrency: usize,
    waves: usize,
    operation: F,
) -> Result<WaveStats, Box<dyn Error>>
where
    F: Fn(usize) -> Result<(), String> + Send + Sync + 'static,
{
    let operation = Arc::new(operation);
    let (result_tx, result_rx) = mpsc::channel::<Result<Duration, String>>();
    let mut command_senders = Vec::with_capacity(concurrency);
    let mut handles = Vec::with_capacity(concurrency);

    for worker_id in 0..concurrency {
        let (command_tx, command_rx) = mpsc::channel::<WorkerCommand>();
        command_senders.push(command_tx);

        let result_tx = result_tx.clone();
        let operation = Arc::clone(&operation);
        handles.push(thread::spawn(move || {
            while let Ok(command) = command_rx.recv() {
                match command {
                    WorkerCommand::Run => {
                        let start = Instant::now();
                        let result = operation(worker_id).map(|()| start.elapsed());
                        if result_tx.send(result).is_err() {
                            break;
                        }
                    }
                    WorkerCommand::Stop => break,
                }
            }
        }));
    }
    drop(result_tx);

    let mut latencies = Vec::with_capacity(concurrency * waves);
    let start = Instant::now();
    for _ in 0..waves {
        for sender in &command_senders {
            sender
                .send(WorkerCommand::Run)
                .map_err(|e| format!("failed to start worker command: {e}"))?;
        }
        for _ in 0..concurrency {
            latencies.push(
                result_rx
                    .recv()
                    .map_err(|e| format!("failed to receive worker result: {e}"))?
                    .map_err(|e| format!("worker operation failed: {e}"))?,
            );
        }
    }
    let elapsed = start.elapsed();

    for sender in command_senders {
        let _ = sender.send(WorkerCommand::Stop);
    }
    for handle in handles {
        handle
            .join()
            .map_err(|_| "concurrent benchmark worker panicked")?;
    }

    Ok(WaveStats {
        total_ops: latencies.len(),
        elapsed,
        latencies,
    })
}

fn percentile_ms(sorted_latencies: &[Duration], percentile: f64) -> f64 {
    if sorted_latencies.is_empty() {
        return 0.0;
    }
    let index = ((sorted_latencies.len() - 1) as f64 * percentile).round() as usize;
    sorted_latencies[index].as_secs_f64() * 1_000.0
}

fn print_result(
    backend: &str,
    operation: &str,
    bytes_or_bits: usize,
    concurrency: usize,
    waves: usize,
    mut stats: WaveStats,
) {
    stats.latencies.sort_unstable();
    let seconds = stats.elapsed.as_secs_f64();
    let ops = stats.total_ops as f64;
    let gbps = if operation.starts_with("aes-") {
        ops * bytes_or_bits as f64 * 8.0 / seconds / 1.0e9
    } else {
        0.0
    };
    let avg_ms = stats
        .latencies
        .iter()
        .map(Duration::as_secs_f64)
        .sum::<f64>()
        * 1_000.0
        / ops;
    println!(
        "hsm_store_concurrent,{backend},{operation},{bytes_or_bits},{concurrency},{waves},{total_ops},{seconds:.9},{ops_s:.3},{gbps:.6},{avg_ms:.3},{p50_ms:.3},{p95_ms:.3},{p99_ms:.3}",
        total_ops = stats.total_ops,
        ops_s = ops / seconds,
        p50_ms = percentile_ms(&stats.latencies, 0.50),
        p95_ms = percentile_ms(&stats.latencies, 0.95),
        p99_ms = percentile_ms(&stats.latencies, 0.99),
    );
}

async fn benchmark_aes_gcm_concurrent(
    store: Arc<HsmStore>,
    uid: String,
    backend: &str,
    message_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    let mut plaintext = vec![0_u8; message_bytes];
    let mut aad = vec![0_u8; 20];
    fill_bytes(&mut plaintext, 17);
    fill_bytes(&mut aad, 0xa0);

    let encrypted = store.encrypt(&uid, &plaintext, None, Some(&aad)).await?;
    let packed = pack_gcm(&encrypted)?;
    let recovered = store.decrypt(&uid, &packed, None, Some(&aad)).await?;
    if recovered.as_slice() != plaintext.as_slice() {
        return Err("HsmStore concurrent AES-GCM warmup roundtrip mismatch".into());
    }

    let plaintext = Arc::new(plaintext);
    let aad = Arc::new(aad);
    let packed = Arc::new(packed);

    for concurrency in [1_usize, 8] {
        let waves = 2;
        let encrypt_store = Arc::clone(&store);
        let encrypt_uid = uid.clone();
        let encrypt_plaintext = Arc::clone(&plaintext);
        let encrypt_aad = Arc::clone(&aad);
        let stats = run_threaded_waves(concurrency, waves, move |_| {
            block_on(encrypt_store.encrypt(
                &encrypt_uid,
                encrypt_plaintext.as_slice(),
                None,
                Some(encrypt_aad.as_slice()),
            ))
            .map(|_| ())
            .map_err(|e| e.to_string())
        })?;
        print_result(
            backend,
            "aes-256-gcm-encrypt",
            message_bytes,
            concurrency,
            waves,
            stats,
        );

        let decrypt_store = Arc::clone(&store);
        let decrypt_uid = uid.clone();
        let decrypt_packed = Arc::clone(&packed);
        let decrypt_aad = Arc::clone(&aad);
        let stats = run_threaded_waves(concurrency, waves, move |_| {
            block_on(decrypt_store.decrypt(
                &decrypt_uid,
                decrypt_packed.as_slice(),
                None,
                Some(decrypt_aad.as_slice()),
            ))
            .map(|_| ())
            .map_err(|e| e.to_string())
        })?;
        print_result(
            backend,
            "aes-256-gcm-decrypt",
            message_bytes,
            concurrency,
            waves,
            stats,
        );
    }

    Ok(())
}

async fn benchmark_rsa_oaep_concurrent(
    store: Arc<HsmStore>,
    public_uid: String,
    private_uid: String,
    backend: &str,
    key_bits: usize,
) -> Result<(), Box<dyn Error>> {
    let mut message = vec![0_u8; 48];
    fill_bytes(&mut message, 0x31);
    let encrypted = store.encrypt(&public_uid, &message, None, None).await?;
    let recovered = store
        .decrypt(&private_uid, &encrypted.ciphertext, None, None)
        .await?;
    if recovered.as_slice() != message.as_slice() {
        return Err("HsmStore concurrent RSA-OAEP-SHA256 warmup roundtrip mismatch".into());
    }

    let message = Arc::new(message);
    let ciphertext = Arc::new(encrypted.ciphertext);

    for concurrency in [1_usize, 8, 32, 64] {
        let waves = 4;
        let encrypt_store = Arc::clone(&store);
        let encrypt_uid = public_uid.clone();
        let encrypt_message = Arc::clone(&message);
        let stats = run_threaded_waves(concurrency, waves, move |_| {
            block_on(encrypt_store.encrypt(&encrypt_uid, encrypt_message.as_slice(), None, None))
                .map(|_| ())
                .map_err(|e| e.to_string())
        })?;
        print_result(
            backend,
            &format!("rsa-{key_bits}-oaep-sha256-encrypt"),
            key_bits,
            concurrency,
            waves,
            stats,
        );

        let decrypt_store = Arc::clone(&store);
        let decrypt_uid = private_uid.clone();
        let decrypt_ciphertext = Arc::clone(&ciphertext);
        let stats = run_threaded_waves(concurrency, waves, move |_| {
            block_on(decrypt_store.decrypt(&decrypt_uid, decrypt_ciphertext.as_slice(), None, None))
                .map(|_| ())
                .map_err(|e| e.to_string())
        })?;
        print_result(
            backend,
            &format!("rsa-{key_bits}-oaep-sha256-decrypt"),
            key_bits,
            concurrency,
            waves,
            stats,
        );
    }

    Ok(())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let backend = env::args().nth(1).unwrap_or_else(|| "unknown".to_owned());
    let only = env::var("SOFTHSM_CLASSIC_BENCH_ONLY").unwrap_or_default();
    let run_aes = only.is_empty() || only == "aes";
    let run_rsa = only.is_empty() || only == "rsa";
    if !run_aes && !run_rsa {
        return Err(format!("invalid SOFTHSM_CLASSIC_BENCH_ONLY value: {only}").into());
    }
    let rsa_bits: usize = env::var("SOFTHSM_CLASSIC_BENCH_RSA_BITS")
        .unwrap_or_else(|_| "2048".to_owned())
        .parse()?;
    if !matches!(rsa_bits, 2048 | 3072 | 4096) {
        return Err(format!("unsupported SOFTHSM_CLASSIC_BENCH_RSA_BITS value: {rsa_bits}").into());
    }
    let lib_path =
        env::var("SOFTHSM2_PKCS11_LIB").unwrap_or_else(|_| SOFTHSM2_PKCS11_LIB.to_owned());
    let slot_id: usize = env::var("HSM_SLOT_ID")?.parse()?;
    let password = env::var("HSM_USER_PASSWORD")?;
    let hsm = Arc::new(Softhsm2::instantiate(
        &lib_path,
        HashMap::from([(slot_id, Some(password))]),
    )?);

    let process_id = std::process::id();
    let aes_id = format!("bench-store-conc-aes-{backend}-{process_id}");
    let rsa_sk_id = format!("bench-store-conc-rsa{rsa_bits}-sk-{backend}-{process_id}");
    let rsa_pk_id = format!("bench-store-conc-rsa{rsa_bits}-pk-{backend}-{process_id}");
    if run_aes {
        hsm.create_key(slot_id, aes_id.as_bytes(), HsmKeyAlgorithm::AES, 256, true)
            .await?;
    }
    if run_rsa {
        hsm.create_keypair(
            slot_id,
            rsa_sk_id.as_bytes(),
            rsa_pk_id.as_bytes(),
            HsmKeypairAlgorithm::RSA,
            rsa_bits,
            true,
        )
        .await?;
    }

    let store = Arc::new(HsmStore::new(hsm, &["*".to_owned()], "softhsm2", "hsm"));
    let aes_uid = format!("hsm::{slot_id}::{aes_id}");
    let rsa_sk_uid = format!("hsm::{slot_id}::{rsa_sk_id}");
    let rsa_pk_uid = format!("hsm::{slot_id}::{rsa_pk_id}");

    if run_aes {
        benchmark_aes_gcm_concurrent(Arc::clone(&store), aes_uid, &backend, 1_048_576).await?;
    }
    if run_rsa {
        benchmark_rsa_oaep_concurrent(store, rsa_pk_uid, rsa_sk_uid, &backend, rsa_bits).await?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    block_on(run())
}
