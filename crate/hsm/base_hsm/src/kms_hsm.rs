//! Implementation of the Hardware Security Module (HSM) trait for `BaseHsm`
//!
//! This implementation provides cryptographic operations using a Hardware Security Module,
//! supporting various key management and cryptographic operations.
//!
//! # Implemented Operations
//!
//! - Key Generation: Create symmetric (AES) and asymmetric (RSA) keys
//! - Key Pair Generation: Create public/private key pairs
//! - Key Export: Export HSM objects
//! - Key Deletion: Remove keys from the HSM
//! - Key Search: Find keys based on object type filters
//! - Encryption/Decryption: Perform cryptographic operations
//! - Key Information: Retrieve key types and metadata
//!
//! # Supported Algorithms
//!
//! - AES: 128-bit and 256-bit keys
//! - RSA: 1024-bit, 2048-bit, 3072-bit, and 4096-bit keys
//!
//! # Error Handling
//!
//! All operations return `InterfaceResult<T>` which may contain:
//! - Errors for duplicate key IDs
//! - Invalid key sizes
//! - Object not found errors
//! - General HSM operation failures
//!
//! # Security Features
//!
//! - Support for sensitive key material handling
//! - Secure session management
//! - Zero-copy cleanup for sensitive data using `Zeroizing`
use std::{
    sync::{Arc, Mutex, OnceLock, mpsc},
    thread,
};

use async_trait::async_trait;
use cosmian_kms_interfaces::{
    CryptoAlgorithm, EncryptedContent, HSM, HsmDecryptBatchRequest, HsmEncryptBatchRequest,
    HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, InterfaceError,
    InterfaceResult, KeyMetadata, KeyType, SigningAlgorithm,
};
use cosmian_logger::debug;
use zeroize::Zeroizing;

use crate::{AesKeySize, BaseHsm, PqcKeypairAlgorithm, RsaKeySize, hsm_capabilities::HsmProvider};

type HsmBatchJob = Box<dyn FnOnce() + Send + 'static>;

struct HsmBatchWorkerPool {
    sender: mpsc::Sender<HsmBatchJob>,
}

impl HsmBatchWorkerPool {
    fn new(worker_count: usize) -> Self {
        let (sender, receiver) = mpsc::channel::<HsmBatchJob>();
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_id in 0..worker_count {
            let receiver = receiver.clone();
            drop(
                thread::Builder::new()
                    .name(format!("hsm-batch-worker-{worker_id}"))
                    .spawn(move || {
                        loop {
                            let job = {
                                let Ok(receiver) = receiver.lock() else {
                                    break;
                                };
                                receiver.recv()
                            };
                            match job {
                                Ok(job) => job(),
                                Err(_) => break,
                            }
                        }
                    }),
            );
        }
        Self { sender }
    }

    fn submit(&self, job: HsmBatchJob) -> InterfaceResult<()> {
        self.sender.send(job).map_err(|_| {
            InterfaceError::Default("failed to submit HSM batch worker job".to_owned())
        })
    }
}

static HSM_BATCH_WORKER_POOL: OnceLock<HsmBatchWorkerPool> = OnceLock::new();

fn configured_hsm_batch_workers() -> usize {
    std::env::var("COSMIAN_HSM_BATCH_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (1..=1024).contains(value))
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(8)
                .clamp(2, 64)
        })
}

fn hsm_batch_worker_pool() -> &'static HsmBatchWorkerPool {
    HSM_BATCH_WORKER_POOL.get_or_init(|| HsmBatchWorkerPool::new(configured_hsm_batch_workers()))
}

fn hsm_batch_worker_pool_enabled() -> bool {
    std::env::var("COSMIAN_HSM_BATCH_WORKER_POOL").is_ok_and(|value| {
        matches!(
            value.as_str(),
            "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
        )
    })
}

fn run_hsm_batch_worker_pool<T, F>(jobs: Vec<F>) -> InterfaceResult<Vec<T>>
where
    T: Send + 'static,
    F: FnOnce() -> InterfaceResult<T> + Send + 'static,
{
    let job_count = jobs.len();
    let (result_sender, result_receiver) = mpsc::channel::<(usize, InterfaceResult<T>)>();
    for (index, job) in jobs.into_iter().enumerate() {
        let result_sender = result_sender.clone();
        hsm_batch_worker_pool().submit(Box::new(move || {
            drop(result_sender.send((index, job())));
        }))?;
    }
    drop(result_sender);

    let mut outputs = Vec::with_capacity(job_count);
    outputs.resize_with(job_count, || None);
    for _ in 0..job_count {
        let (index, result) = result_receiver.recv().map_err(|_| {
            InterfaceError::Default("failed to receive HSM batch worker result".to_owned())
        })?;
        outputs[index] = Some(result?);
    }

    outputs
        .into_iter()
        .map(|output| {
            output.ok_or_else(|| {
                InterfaceError::Default("missing HSM batch worker result".to_owned())
            })
        })
        .collect()
}

fn hsm_batch_parallel_rsa_enabled() -> bool {
    std::env::var("COSMIAN_HSM_BATCH_PARALLEL_RSA")
        .or_else(|_| std::env::var("COSMIAN_HSM_BATCH_PARALLEL"))
        .is_ok_and(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
}

fn hsm_batch_rsa_fixed_output_len_enabled() -> bool {
    std::env::var("COSMIAN_HSM_RSA_FIXED_OUTPUT_LEN").is_ok_and(|value| {
        matches!(
            value.as_str(),
            "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
        )
    })
}

fn is_rsa_batch_algorithm(algorithm: &CryptoAlgorithm) -> bool {
    matches!(
        algorithm,
        CryptoAlgorithm::RsaPkcsV15 | CryptoAlgorithm::RsaOaepSha256 | CryptoAlgorithm::RsaOaepSha1
    )
}

#[async_trait]
impl<P: HsmProvider> HSM for BaseHsm<P> {
    async fn get_available_slot_list(&self) -> InterfaceResult<Vec<usize>> {
        Ok(self.get_available_slot_list()?)
    }

    async fn get_supported_algorithms(
        &self,
        slot_id: usize,
    ) -> InterfaceResult<Vec<CryptoAlgorithm>> {
        Ok(self.get_algorithms(slot_id)?)
    }

    async fn create_key(
        &self,
        slot_id: usize,
        id: &[u8],
        algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
    ) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;

        if session.get_object_handle(id).is_ok() {
            return Err(InterfaceError::Default(
                "A secret key with this id already exists".to_owned(),
            ));
        }

        match algorithm {
            HsmKeyAlgorithm::AES => {
                let key_size = match key_length_in_bits {
                    128 => AesKeySize::Aes128,
                    256 => AesKeySize::Aes256,
                    x => {
                        return Err(InterfaceError::Default(format!(
                            "Invalid key length: {x} bits, for and HSM AES key"
                        )));
                    }
                };
                let _ = session.generate_aes_key(id, key_size, sensitive)?;
                Ok(())
            }
        }
    }

    async fn create_keypair(
        &self,
        slot_id: usize,
        sk_id: &[u8],
        pk_id: &[u8],
        algorithm: HsmKeypairAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
    ) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;

        if session.get_object_handle(sk_id).is_ok() {
            return Err(InterfaceError::Default(
                "A private key with this ID already exists".to_owned(),
            ));
        }
        if session.get_object_handle(pk_id).is_ok() {
            return Err(InterfaceError::Default(
                "A public key with this ID and the '_pk' suffix already exists".to_owned(),
            ));
        }

        match algorithm {
            HsmKeypairAlgorithm::RSA => {
                let key_length_in_bits = match key_length_in_bits {
                    1024 => RsaKeySize::Rsa1024,
                    2048 => RsaKeySize::Rsa2048,
                    3072 => RsaKeySize::Rsa3072,
                    4096 => RsaKeySize::Rsa4096,
                    x => {
                        return Err(InterfaceError::Default(format!(
                            "Invalid key length: {x} bits, for and HSM RSA key (valid values are \
                             1024, 2048, 3072, 4096)"
                        )));
                    }
                };
                session.generate_rsa_key_pair(sk_id, pk_id, key_length_in_bits, sensitive)?;
                Ok(())
            }
            HsmKeypairAlgorithm::MlKem512 => {
                session.generate_pqc_key_pair(
                    sk_id,
                    pk_id,
                    PqcKeypairAlgorithm::MlKem512,
                    sensitive,
                )?;
                Ok(())
            }
            HsmKeypairAlgorithm::MlKem768 => {
                session.generate_pqc_key_pair(
                    sk_id,
                    pk_id,
                    PqcKeypairAlgorithm::MlKem768,
                    sensitive,
                )?;
                Ok(())
            }
            HsmKeypairAlgorithm::MlKem1024 => {
                session.generate_pqc_key_pair(
                    sk_id,
                    pk_id,
                    PqcKeypairAlgorithm::MlKem1024,
                    sensitive,
                )?;
                Ok(())
            }
            HsmKeypairAlgorithm::MlDsa44 => {
                session.generate_pqc_key_pair(
                    sk_id,
                    pk_id,
                    PqcKeypairAlgorithm::MlDsa44,
                    sensitive,
                )?;
                Ok(())
            }
            HsmKeypairAlgorithm::MlDsa65 => {
                session.generate_pqc_key_pair(
                    sk_id,
                    pk_id,
                    PqcKeypairAlgorithm::MlDsa65,
                    sensitive,
                )?;
                Ok(())
            }
            HsmKeypairAlgorithm::MlDsa87 => {
                session.generate_pqc_key_pair(
                    sk_id,
                    pk_id,
                    PqcKeypairAlgorithm::MlDsa87,
                    sensitive,
                )?;
                Ok(())
            }
        }
    }

    async fn export(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<Option<HsmObject>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(object_id)?;
        let object = session.export_key(handle)?;
        Ok(object)
    }

    async fn delete(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(object_id)?;
        session.destroy_object(handle)?;
        session.delete_object_handle(object_id)?;
        Ok(())
    }

    async fn find(
        &self,
        slot_id: usize,
        object_filter: HsmObjectFilter,
    ) -> InterfaceResult<Vec<Vec<u8>>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handles = session.list_objects(object_filter)?;
        let mut object_ids = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Ok(Some(object_id)) = session.get_object_id(handle) {
                // Pre-populate the object handle cache so that subsequent
                // export()/get_object_handle() calls get a cache hit instead of
                // re-searching via find_by_id_or_label() which may fail due to
                // CKA_ID/CKA_LABEL asymmetry.
                drop(session.cache_object_handle(&object_id, handle));
                object_ids.push(object_id);
            } else {
                debug!("Invalid object, skipping");
            }
        }
        Ok(object_ids)
    }

    async fn encrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
        authenticated_encryption_additional_data: &[u8],
    ) -> InterfaceResult<EncryptedContent> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let encrypted_content = session.encrypt_with_aad(
            handle,
            algorithm.into(),
            data,
            authenticated_encryption_additional_data,
        )?;
        Ok(encrypted_content)
    }

    async fn encrypt_batch(
        &self,
        requests: &[HsmEncryptBatchRequest],
    ) -> InterfaceResult<Vec<EncryptedContent>> {
        let mut responses = Vec::with_capacity(requests.len());
        let mut index = 0;
        while index < requests.len() {
            let request = &requests[index];
            let slot = self.get_slot(request.slot_id)?;
            let slot_id = request.slot_id;
            let key_id = request.key_id.clone();
            let algorithm = request.algorithm.clone();
            let mut segment_end = index + 1;
            while segment_end < requests.len() {
                let request = &requests[segment_end];
                if request.slot_id != slot_id
                    || request.key_id != key_id
                    || request.algorithm != algorithm
                {
                    break;
                }
                segment_end += 1;
            }

            if segment_end - index > 1
                && hsm_batch_parallel_rsa_enabled()
                && is_rsa_batch_algorithm(&algorithm)
            {
                let fixed_output_len = if hsm_batch_rsa_fixed_output_len_enabled() {
                    let session = slot.open_session(true)?;
                    let handle = session.get_object_handle(&key_id)?;
                    session.rsa_modulus_len(handle).ok().flatten()
                } else {
                    None
                };
                if hsm_batch_worker_pool_enabled() {
                    let mut jobs = Vec::with_capacity(segment_end - index);
                    for request in &requests[index..segment_end] {
                        let slot = slot.clone();
                        let key_id = request.key_id.clone();
                        let algorithm = request.algorithm.clone();
                        let data = request.data.clone();
                        let aad = request.authenticated_encryption_additional_data.clone();
                        jobs.push(move || -> InterfaceResult<EncryptedContent> {
                            let session = slot.open_session(true)?;
                            let handle = session.get_object_handle(&key_id)?;
                            Ok(session.encrypt_with_aad_and_output_len(
                                handle,
                                algorithm.into(),
                                &data,
                                &aad,
                                fixed_output_len,
                            )?)
                        });
                    }
                    let mut segment_responses = run_hsm_batch_worker_pool(jobs)?;
                    responses.append(&mut segment_responses);
                    index = segment_end;
                    continue;
                }
                let mut segment_responses = std::thread::scope(|scope| {
                    let mut handles = Vec::with_capacity(segment_end - index);
                    for request in &requests[index..segment_end] {
                        let slot = slot.clone();
                        let key_id = request.key_id.clone();
                        let algorithm = request.algorithm.clone();
                        let data = request.data.clone();
                        let aad = request.authenticated_encryption_additional_data.clone();
                        handles.push(scope.spawn(move || -> InterfaceResult<EncryptedContent> {
                            let session = slot.open_session(true)?;
                            let handle = session.get_object_handle(&key_id)?;
                            Ok(session.encrypt_with_aad_and_output_len(
                                handle,
                                algorithm.into(),
                                &data,
                                &aad,
                                fixed_output_len,
                            )?)
                        }));
                    }

                    let mut outputs = Vec::with_capacity(handles.len());
                    for handle in handles {
                        outputs.push(handle.join().map_err(|_| {
                            InterfaceError::Default(
                                "parallel HSM RSA encrypt worker panicked".to_owned(),
                            )
                        })??);
                    }
                    InterfaceResult::Ok(outputs)
                })?;
                responses.append(&mut segment_responses);
                index = segment_end;
                continue;
            }

            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&key_id)?;
            let fixed_output_len =
                if hsm_batch_rsa_fixed_output_len_enabled() && is_rsa_batch_algorithm(&algorithm) {
                    session.rsa_modulus_len(handle).ok().flatten()
                } else {
                    None
                };
            while index < segment_end {
                let request = &requests[index];
                responses.push(session.encrypt_with_aad_and_output_len(
                    handle,
                    algorithm.clone().into(),
                    &request.data,
                    &request.authenticated_encryption_additional_data,
                    fixed_output_len,
                )?);
                index += 1;
            }
        }
        Ok(responses)
    }

    async fn decrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
        authenticated_encryption_additional_data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let plaintext = session.decrypt_with_aad(
            handle,
            algorithm.into(),
            data,
            authenticated_encryption_additional_data,
        )?;
        Ok(plaintext)
    }

    async fn decrypt_batch(
        &self,
        requests: &[HsmDecryptBatchRequest],
    ) -> InterfaceResult<Vec<Zeroizing<Vec<u8>>>> {
        let mut responses = Vec::with_capacity(requests.len());
        let mut index = 0;
        while index < requests.len() {
            let request = &requests[index];
            let slot = self.get_slot(request.slot_id)?;
            let slot_id = request.slot_id;
            let key_id = request.key_id.clone();
            let algorithm = request.algorithm.clone();
            let mut segment_end = index + 1;
            while segment_end < requests.len() {
                let request = &requests[segment_end];
                if request.slot_id != slot_id
                    || request.key_id != key_id
                    || request.algorithm != algorithm
                {
                    break;
                }
                segment_end += 1;
            }

            if segment_end - index > 1
                && hsm_batch_parallel_rsa_enabled()
                && is_rsa_batch_algorithm(&algorithm)
            {
                let fixed_output_len = if hsm_batch_rsa_fixed_output_len_enabled() {
                    let session = slot.open_session(true)?;
                    let handle = session.get_object_handle(&key_id)?;
                    session.rsa_modulus_len(handle).ok().flatten()
                } else {
                    None
                };
                if hsm_batch_worker_pool_enabled() {
                    let mut jobs = Vec::with_capacity(segment_end - index);
                    for request in &requests[index..segment_end] {
                        let slot = slot.clone();
                        let key_id = request.key_id.clone();
                        let algorithm = request.algorithm.clone();
                        let data = request.data.clone();
                        let aad = request.authenticated_encryption_additional_data.clone();
                        jobs.push(move || -> InterfaceResult<Zeroizing<Vec<u8>>> {
                            let session = slot.open_session(true)?;
                            let handle = session.get_object_handle(&key_id)?;
                            Ok(session.decrypt_with_aad_and_output_len(
                                handle,
                                algorithm.into(),
                                &data,
                                &aad,
                                fixed_output_len,
                            )?)
                        });
                    }
                    let mut segment_responses = run_hsm_batch_worker_pool(jobs)?;
                    responses.append(&mut segment_responses);
                    index = segment_end;
                    continue;
                }
                let mut segment_responses = std::thread::scope(|scope| {
                    let mut handles = Vec::with_capacity(segment_end - index);
                    for request in &requests[index..segment_end] {
                        let slot = slot.clone();
                        let key_id = request.key_id.clone();
                        let algorithm = request.algorithm.clone();
                        let data = request.data.clone();
                        let aad = request.authenticated_encryption_additional_data.clone();
                        handles.push(scope.spawn(
                            move || -> InterfaceResult<Zeroizing<Vec<u8>>> {
                                let session = slot.open_session(true)?;
                                let handle = session.get_object_handle(&key_id)?;
                                Ok(session.decrypt_with_aad_and_output_len(
                                    handle,
                                    algorithm.into(),
                                    &data,
                                    &aad,
                                    fixed_output_len,
                                )?)
                            },
                        ));
                    }

                    let mut outputs = Vec::with_capacity(handles.len());
                    for handle in handles {
                        outputs.push(handle.join().map_err(|_| {
                            InterfaceError::Default(
                                "parallel HSM RSA decrypt worker panicked".to_owned(),
                            )
                        })??);
                    }
                    InterfaceResult::Ok(outputs)
                })?;
                responses.append(&mut segment_responses);
                index = segment_end;
                continue;
            }

            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&key_id)?;
            let fixed_output_len =
                if hsm_batch_rsa_fixed_output_len_enabled() && is_rsa_batch_algorithm(&algorithm) {
                    session.rsa_modulus_len(handle).ok().flatten()
                } else {
                    None
                };
            while index < segment_end {
                let request = &requests[index];
                responses.push(session.decrypt_with_aad_and_output_len(
                    handle,
                    algorithm.clone().into(),
                    &request.data,
                    &request.authenticated_encryption_additional_data,
                    fixed_output_len,
                )?);
                index += 1;
            }
        }
        Ok(responses)
    }

    async fn sign(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: SigningAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Vec<u8>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let signature = session.sign(handle, algorithm.into(), data)?;
        Ok(signature)
    }

    async fn signature_verify(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: SigningAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> InterfaceResult<bool> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let verified = session.signature_verify(handle, algorithm.into(), data, signature)?;
        Ok(verified)
    }

    async fn get_key_type(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyType>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let key_type = session.get_key_type(handle)?;
        Ok(key_type)
    }

    async fn get_key_metadata(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyMetadata>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let metadata = session.get_key_metadata(handle)?;
        Ok(metadata)
    }

    async fn generate_random(&self, slot_id: usize, len: usize) -> InterfaceResult<Vec<u8>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let bytes = session.generate_random(len)?;
        Ok(bytes)
    }

    async fn seed_random(&self, slot_id: usize, seed: &[u8]) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let () = session.seed_random(seed)?;
        Ok(())
    }

    fn hsm_lib(&self) -> Option<&dyn std::any::Any> {
        Some(self.hsm_lib())
    }
}
