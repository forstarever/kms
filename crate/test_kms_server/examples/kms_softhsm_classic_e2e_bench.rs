#![allow(clippy::print_stdout)]

use std::{
    env,
    error::Error,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use cosmian_kms_client::{
    KmsClient,
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{BlockCipherMode, PaddingMethod, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::Operation,
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
        requests::{
            create_rsa_key_pair_request, decrypt_request, encrypt_request,
            symmetric_key_create_request,
        },
    },
};
use cosmian_kms_server::config::{ClapConfig, HsmConfig};
use test_kms_server::start_test_kms_server_with_config;

fn fill_bytes(buffer: &mut [u8], seed: u8) {
    let mut state = seed;
    for byte in buffer.iter_mut() {
        state = state.wrapping_mul(131).wrapping_add(17);
        *byte = state;
    }
}

fn aes_iterations_for(message_bytes: usize) -> u32 {
    let target = 4_usize * 1024 * 1024;
    let mut iterations = if message_bytes == 0 {
        1
    } else {
        target / message_bytes
    };
    iterations = iterations.clamp(2, 64);
    u32::try_from(iterations).unwrap_or(64)
}

fn rsa_iterations_for(operation: &str) -> u32 {
    if operation.contains("encrypt") {
        64
    } else {
        16
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
        "kms_http,{backend},{operation},{bytes_or_bits},1,{iterations},{seconds:.9},{ops_s:.3},{gbps:.6}",
        ops_s = ops / seconds
    );
}

fn print_batch_result(
    backend: &str,
    operation: &str,
    bytes_or_bits: usize,
    batch: usize,
    iterations: u32,
    elapsed: Duration,
) {
    let seconds = elapsed.as_secs_f64();
    let ops = f64::from(iterations) * batch as f64;
    println!(
        "kms_http_message_batch,{backend},{operation},{bytes_or_bits},{batch},{iterations},{seconds:.9},{ops_s:.3},0.000000",
        ops_s = ops / seconds
    );
}

fn unique_id(prefix: &str, backend: &str, slot_id: usize) -> String {
    format!(
        "hsm::{slot_id}::{prefix}-{backend}-{pid}",
        pid = std::process::id()
    )
}

fn workspace_path(name: &str, backend: &str) -> PathBuf {
    env::temp_dir().join(format!(
        "kms-softhsm-http-{name}-{backend}-{pid}",
        pid = std::process::id()
    ))
}

fn server_config(
    slot_id: usize,
    password: String,
    backend: &str,
) -> Result<ClapConfig, Box<dyn Error>> {
    let workspace = workspace_path("workspace", backend);
    let tmp = workspace_path("tmp", backend);
    let sqlite = workspace_path("sqlite", backend);
    fs::create_dir_all(&workspace)?;
    fs::create_dir_all(&tmp)?;
    fs::create_dir_all(&sqlite)?;

    let mut config = ClapConfig::default();
    config.default_username = "admin".to_owned();
    config.hsm = HsmConfig {
        hsm_model: "softhsm2".to_owned(),
        hsm_admin: vec!["admin".to_owned()],
        hsm_slot: vec![slot_id],
        hsm_password: vec![password],
    };
    config.db.database_type = Some("sqlite".to_owned());
    config.db.sqlite_path = sqlite;
    config.db.clear_database = true;
    config.workspace.root_data_path = workspace;
    config.workspace.tmp_path = tmp;
    config.http.hostname = "127.0.0.1".to_owned();
    config.http.port = 0;
    Ok(config)
}

fn aes_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::GCM),
        ..Default::default()
    }
}

fn rsa_oaep_sha256_params() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        padding_method: Some(PaddingMethod::OAEP),
        ..Default::default()
    }
}

async fn create_aes_key(client: &KmsClient, uid: &str) -> Result<(), Box<dyn Error>> {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(uid.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        Vec::<String>::new(),
        true,
        None,
    )?;
    let response = client.create(request).await?;
    if response.unique_identifier != UniqueIdentifier::TextString(uid.to_owned()) {
        return Err(format!("unexpected AES key id: {:?}", response.unique_identifier).into());
    }
    Ok(())
}

async fn create_rsa_keypair(
    client: &KmsClient,
    private_uid: &str,
) -> Result<String, Box<dyn Error>> {
    let request = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(private_uid.to_owned())),
        Vec::<String>::new(),
        2048,
        true,
        None,
    )?;
    let response = client.create_key_pair(request).await?;
    if response.private_key_unique_identifier
        != UniqueIdentifier::TextString(private_uid.to_owned())
    {
        return Err(format!(
            "unexpected RSA private key id: {:?}",
            response.private_key_unique_identifier
        )
        .into());
    }
    Ok(response.public_key_unique_identifier.to_string())
}

async fn aes_encrypt(
    client: &KmsClient,
    uid: &str,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let response = client
        .encrypt(encrypt_request(
            uid,
            None,
            plaintext,
            None,
            Some(aad),
            Some(aes_params()),
        )?)
        .await?;
    Ok((
        response.i_v_counter_nonce.unwrap_or_default(),
        response.data.unwrap_or_default(),
        response.authenticated_encryption_tag.unwrap_or_default(),
    ))
}

async fn aes_decrypt(
    client: &KmsClient,
    uid: &str,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let response = client
        .decrypt(decrypt_request(
            uid,
            Some(nonce),
            ciphertext,
            Some(tag),
            Some(aad),
            Some(aes_params()),
        ))
        .await?;
    Ok(response.data.unwrap_or_default().to_vec())
}

async fn benchmark_aes_gcm(
    client: &KmsClient,
    uid: &str,
    backend: &str,
    message_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    let mut plaintext = vec![0_u8; message_bytes];
    let mut aad = vec![0_u8; 20];
    fill_bytes(&mut plaintext, 17);
    fill_bytes(&mut aad, 0xa0);

    let (nonce, ciphertext, tag) = aes_encrypt(client, uid, plaintext.clone(), aad.clone()).await?;
    let recovered = aes_decrypt(client, uid, nonce, ciphertext, tag, aad.clone()).await?;
    if recovered != plaintext {
        return Err("KMS HTTP AES-GCM warmup roundtrip mismatch".into());
    }

    let iterations = aes_iterations_for(message_bytes);
    let start = Instant::now();
    let mut last = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..iterations {
        last = aes_encrypt(client, uid, plaintext.clone(), aad.clone()).await?;
    }
    print_result(
        backend,
        "aes-256-gcm-encrypt",
        message_bytes,
        iterations,
        start.elapsed(),
    );

    let iterations = aes_iterations_for(message_bytes);
    let start = Instant::now();
    for _ in 0..iterations {
        drop(
            aes_decrypt(
                client,
                uid,
                last.0.clone(),
                last.1.clone(),
                last.2.clone(),
                aad.clone(),
            )
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

async fn rsa_encrypt(
    client: &KmsClient,
    public_uid: &str,
    message: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let response = client
        .encrypt(encrypt_request(
            public_uid,
            None,
            message,
            None,
            None,
            Some(rsa_oaep_sha256_params()),
        )?)
        .await?;
    Ok(response.data.unwrap_or_default())
}

async fn rsa_decrypt(
    client: &KmsClient,
    private_uid: &str,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let response = client
        .decrypt(decrypt_request(
            private_uid,
            None,
            ciphertext,
            None,
            None,
            Some(rsa_oaep_sha256_params()),
        ))
        .await?;
    Ok(response.data.unwrap_or_default().to_vec())
}

fn ensure_message_success(
    response: &ResponseMessage,
    expected_items: usize,
) -> Result<(), Box<dyn Error>> {
    if response.batch_item.len() != expected_items {
        return Err(format!(
            "unexpected KMIP message response item count: expected {expected_items}, got {}",
            response.batch_item.len()
        )
        .into());
    }
    for (index, item) in response.batch_item.iter().enumerate() {
        let status = match item {
            ResponseMessageBatchItemVersioned::V14(item) => item.result_status,
            ResponseMessageBatchItemVersioned::V21(item) => item.result_status,
        };
        if status != ResultStatusEnumeration::Success {
            return Err(
                format!("KMIP message batch item {index} failed with status {status:?}").into(),
            );
        }
    }
    Ok(())
}

fn rsa_encrypt_message(
    public_uid: &str,
    message: &[u8],
    batch: usize,
) -> Result<RequestMessage, Box<dyn Error>> {
    let request = encrypt_request(
        public_uid,
        None,
        message.to_vec(),
        None,
        None,
        Some(rsa_oaep_sha256_params()),
    )?;
    Ok(RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: i32::try_from(batch)?,
            ..Default::default()
        },
        batch_item: (0..batch)
            .map(|_| {
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                    Operation::Encrypt(Box::new(request.clone())),
                ))
            })
            .collect(),
    })
}

fn rsa_decrypt_message(
    private_uid: &str,
    ciphertext: &[u8],
    batch: usize,
) -> Result<RequestMessage, Box<dyn Error>> {
    let request = decrypt_request(
        private_uid,
        None,
        ciphertext.to_vec(),
        None,
        None,
        Some(rsa_oaep_sha256_params()),
    );
    Ok(RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: i32::try_from(batch)?,
            ..Default::default()
        },
        batch_item: (0..batch)
            .map(|_| {
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                    Operation::Decrypt(Box::new(request.clone())),
                ))
            })
            .collect(),
    })
}

async fn benchmark_rsa_oaep(
    client: &KmsClient,
    public_uid: &str,
    private_uid: &str,
    backend: &str,
) -> Result<(), Box<dyn Error>> {
    let mut message = vec![0_u8; 48];
    fill_bytes(&mut message, 0x31);
    let ciphertext = rsa_encrypt(client, public_uid, message.clone()).await?;
    let recovered = rsa_decrypt(client, private_uid, ciphertext.clone()).await?;
    if recovered != message {
        return Err("KMS HTTP RSA-OAEP-SHA256 warmup roundtrip mismatch".into());
    }

    let iterations = rsa_iterations_for("rsa-2048-oaep-sha256-encrypt");
    let start = Instant::now();
    let mut last_ciphertext = ciphertext;
    for _ in 0..iterations {
        last_ciphertext = rsa_encrypt(client, public_uid, message.clone()).await?;
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
        drop(rsa_decrypt(client, private_uid, last_ciphertext.clone()).await?);
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

async fn benchmark_rsa_oaep_message_batch(
    client: &KmsClient,
    public_uid: &str,
    private_uid: &str,
    backend: &str,
) -> Result<(), Box<dyn Error>> {
    let mut message = vec![0_u8; 48];
    fill_bytes(&mut message, 0x31);
    let ciphertext = rsa_encrypt(client, public_uid, message.clone()).await?;
    let recovered = rsa_decrypt(client, private_uid, ciphertext.clone()).await?;
    if recovered != message {
        return Err("KMS HTTP RSA-OAEP-SHA256 message-batch warmup mismatch".into());
    }

    for batch in [8_usize, 32, 64] {
        let encrypt_message = rsa_encrypt_message(public_uid, &message, batch)?;
        let response = client.message(encrypt_message.clone()).await?;
        ensure_message_success(&response, batch)?;

        let iterations = 4_u32;
        let start = Instant::now();
        for _ in 0..iterations {
            let response = client.message(encrypt_message.clone()).await?;
            ensure_message_success(&response, batch)?;
        }
        print_batch_result(
            backend,
            "rsa-2048-oaep-sha256-encrypt",
            2048,
            batch,
            iterations,
            start.elapsed(),
        );

        let decrypt_message = rsa_decrypt_message(private_uid, &ciphertext, batch)?;
        let response = client.message(decrypt_message.clone()).await?;
        ensure_message_success(&response, batch)?;

        let iterations = 2_u32;
        let start = Instant::now();
        for _ in 0..iterations {
            let response = client.message(decrypt_message.clone()).await?;
            ensure_message_success(&response, batch)?;
        }
        print_batch_result(
            backend,
            "rsa-2048-oaep-sha256-decrypt",
            2048,
            batch,
            iterations,
            start.elapsed(),
        );
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let backend = env::args().nth(1).unwrap_or_else(|| "unknown".to_owned());
    let slot_id: usize = env::var("HSM_SLOT_ID")?.parse()?;
    let password = env::var("HSM_USER_PASSWORD")?;

    let config = server_config(slot_id, password, &backend)?;
    let context = start_test_kms_server_with_config(config).await;
    let client = context.get_owner_client();

    let aes_uid = unique_id("bench-http-aes", &backend, slot_id);
    let rsa_private_uid = unique_id("bench-http-rsa-sk", &backend, slot_id);
    create_aes_key(&client, &aes_uid).await?;
    let rsa_public_uid = create_rsa_keypair(&client, &rsa_private_uid).await?;

    for message_bytes in [64_usize, 65_536, 1_048_576] {
        benchmark_aes_gcm(&client, &aes_uid, &backend, message_bytes).await?;
    }
    benchmark_rsa_oaep(&client, &rsa_public_uid, &rsa_private_uid, &backend).await?;
    benchmark_rsa_oaep_message_batch(&client, &rsa_public_uid, &rsa_private_uid, &backend).await?;
    Ok(())
}
