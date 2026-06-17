use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM,
    CK_MECHANISM_PTR, CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG,
    CKA_CLASS, CKA_EXTRACTABLE, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE, CKA_SENSITIVE,
    CKA_SIGN, CKA_TOKEN, CKA_UNWRAP, CKA_VALUE, CKA_VALUE_LEN, CKA_VERIFY, CKA_WRAP,
    CKK_GENERIC_SECRET, CKO_SECRET_KEY, CKR_OK, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
};
use zeroize::Zeroizing;

use crate::{HError, HResult, hsm_call, session::Session};

pub(crate) const CKK_ML_KEM: CK_KEY_TYPE = 0x49;
pub(crate) const CKK_ML_DSA: CK_KEY_TYPE = 0x4a;

pub(crate) const CKA_PARAMETER_SET: CK_ATTRIBUTE_TYPE = 0x61d;
pub(crate) const CKA_ML_DSA_PARAMS: CK_ATTRIBUTE_TYPE = 0x638;

pub(crate) const CKM_ML_KEM_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x0f;
pub(crate) const CKM_ML_KEM: CK_MECHANISM_TYPE = 0x17;
pub(crate) const CKM_ML_DSA_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x1c;
pub(crate) const CKM_ML_DSA: CK_MECHANISM_TYPE = 0x1d;

pub(crate) const CKP_ML_KEM_512: CK_ULONG = 1;
pub(crate) const CKP_ML_KEM_768: CK_ULONG = 2;
pub(crate) const CKP_ML_KEM_1024: CK_ULONG = 3;

pub(crate) const CKP_ML_DSA_44: CK_ULONG = 1;
pub(crate) const CKP_ML_DSA_65: CK_ULONG = 2;
pub(crate) const CKP_ML_DSA_87: CK_ULONG = 3;

#[derive(Debug, Clone, Copy)]
pub enum PqcKeypairAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl PqcKeypairAlgorithm {
    const fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => CKM_ML_KEM_KEY_PAIR_GEN,
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => CKM_ML_DSA_KEY_PAIR_GEN,
        }
    }

    const fn key_type(self) -> CK_KEY_TYPE {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => CKK_ML_KEM,
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => CKK_ML_DSA,
        }
    }

    const fn param_attr(self) -> CK_ATTRIBUTE_TYPE {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => CKA_PARAMETER_SET,
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => CKA_ML_DSA_PARAMS,
        }
    }

    const fn parameter_set(self) -> CK_ULONG {
        match self {
            Self::MlKem512 => CKP_ML_KEM_512,
            Self::MlKem768 => CKP_ML_KEM_768,
            Self::MlKem1024 => CKP_ML_KEM_1024,
            Self::MlDsa44 => CKP_ML_DSA_44,
            Self::MlDsa65 => CKP_ML_DSA_65,
            Self::MlDsa87 => CKP_ML_DSA_87,
        }
    }

    const fn is_mlkem(self) -> bool {
        matches!(self, Self::MlKem512 | Self::MlKem768 | Self::MlKem1024)
    }
}

pub(crate) fn mlkem_ciphertext_len(parameter_set: CK_ULONG) -> HResult<usize> {
    match parameter_set {
        CKP_ML_KEM_512 => Ok(768),
        CKP_ML_KEM_768 => Ok(1088),
        CKP_ML_KEM_1024 => Ok(1568),
        x => Err(HError::Default(format!(
            "Unsupported ML-KEM parameter set: {x}"
        ))),
    }
}

pub(crate) fn pqc_key_length_in_bits(
    key_type: CK_KEY_TYPE,
    parameter_set: CK_ULONG,
) -> HResult<usize> {
    match (key_type, parameter_set) {
        (CKK_ML_KEM, CKP_ML_KEM_512) => Ok(512),
        (CKK_ML_KEM, CKP_ML_KEM_768) => Ok(768),
        (CKK_ML_KEM, CKP_ML_KEM_1024) => Ok(1024),
        (CKK_ML_DSA, CKP_ML_DSA_44) => Ok(44),
        (CKK_ML_DSA, CKP_ML_DSA_65) => Ok(65),
        (CKK_ML_DSA, CKP_ML_DSA_87) => Ok(87),
        (key_type, parameter_set) => Err(HError::Default(format!(
            "Unsupported PQC key type/parameter set: {key_type}/{parameter_set}"
        ))),
    }
}

impl Session {
    pub fn generate_pqc_key_pair(
        &self,
        sk_id: &[u8],
        pk_id: &[u8],
        algorithm: PqcKeypairAlgorithm,
        sensitive: bool,
    ) -> HResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let key_type = algorithm.key_type();
        let parameter_set = algorithm.parameter_set();
        let sensitive = if sensitive { CK_TRUE } else { CK_FALSE };
        let extractable = if sensitive == CK_TRUE {
            CK_FALSE
        } else {
            CK_TRUE
        };

        let mut pub_key_template = vec![
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&key_type)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: std::ptr::from_ref(&CK_FALSE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: pk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(pk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID,
                pValue: pk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(pk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: algorithm.param_attr(),
                pValue: std::ptr::from_ref(&parameter_set)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
        ];
        if algorithm.is_mlkem() {
            pub_key_template.push(CK_ATTRIBUTE {
                type_: CKA_WRAP,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            });
        } else {
            pub_key_template.push(CK_ATTRIBUTE {
                type_: CKA_VERIFY,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            });
        }

        let mut priv_key_template = vec![
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&key_type)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: sk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(sk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID,
                pValue: sk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(sk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: std::ptr::from_ref(&sensitive)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXTRACTABLE,
                pValue: std::ptr::from_ref(&extractable)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: algorithm.param_attr(),
                pValue: std::ptr::from_ref(&parameter_set)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
        ];
        if algorithm.is_mlkem() {
            priv_key_template.push(CK_ATTRIBUTE {
                type_: CKA_UNWRAP,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            });
        } else {
            priv_key_template.push(CK_ATTRIBUTE {
                type_: CKA_SIGN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            });
        }

        let mut mechanism = CK_MECHANISM {
            mechanism: algorithm.mechanism(),
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut pub_key_handle = CK_OBJECT_HANDLE::default();
        let mut priv_key_handle = CK_OBJECT_HANDLE::default();
        let p_mechanism: CK_MECHANISM_PTR = &raw mut mechanism;

        hsm_call!(
            self.hsm(),
            "Failed generating PQC key pair",
            C_GenerateKeyPair,
            self.session_handle(),
            p_mechanism,
            pub_key_template.as_mut_ptr(),
            CK_ULONG::try_from(pub_key_template.len())?,
            priv_key_template.as_mut_ptr(),
            CK_ULONG::try_from(priv_key_template.len())?,
            &raw mut pub_key_handle,
            &raw mut priv_key_handle
        );

        self.object_handles_cache()
            .insert(sk_id.to_vec(), priv_key_handle)?;
        self.object_handles_cache()
            .insert(pk_id.to_vec(), pub_key_handle)?;

        Ok((priv_key_handle, pub_key_handle))
    }

    pub fn mlkem_encapsulate(
        &self,
        public_key_handle: CK_OBJECT_HANDLE,
    ) -> HResult<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let parameter_set = self.read_pqc_parameter_set(public_key_handle, CKA_PARAMETER_SET)?;
        let mut ciphertext = vec![0_u8; mlkem_ciphertext_len(parameter_set)?];
        let mut ciphertext_len = CK_ULONG::try_from(ciphertext.len())?;
        let mut secret_handle = CK_OBJECT_HANDLE::default();
        let secret_class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
        let generic_type: CK_KEY_TYPE = CKK_GENERIC_SECRET;
        let value_len: CK_ULONG = 32;
        let ck_false = CK_FALSE;
        let ck_true = CK_TRUE;
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_ML_KEM,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut secret_template = Self::mlkem_secret_template(
            &secret_class,
            &generic_type,
            &value_len,
            &ck_false,
            &ck_true,
        )?;
        let hsm = self.hsm();
        let encapsulate = hsm.C_EncapsulateKey.ok_or_else(|| {
            HError::Default("C_EncapsulateKey not available on library".to_owned())
        })?;

        #[expect(unsafe_code)]
        let rv = unsafe {
            encapsulate(
                self.session_handle(),
                &raw mut mechanism,
                public_key_handle,
                secret_template.as_mut_ptr(),
                CK_ULONG::try_from(secret_template.len())?,
                ciphertext.as_mut_ptr(),
                &raw mut ciphertext_len,
                &raw mut secret_handle,
            )
        };
        if rv != CKR_OK {
            return Err(HError::Default(format!(
                "Failed ML-KEM encapsulation. Return code: {rv}"
            )));
        }
        ciphertext.truncate(usize::try_from(ciphertext_len)?);
        let shared_secret = self.read_secret_value(secret_handle)?;
        self.destroy_object(secret_handle)?;
        Ok((Zeroizing::new(shared_secret), ciphertext))
    }

    pub fn mlkem_decapsulate(
        &self,
        private_key_handle: CK_OBJECT_HANDLE,
        ciphertext: &[u8],
    ) -> HResult<Zeroizing<Vec<u8>>> {
        let mut ciphertext = ciphertext.to_vec();
        let mut secret_handle = CK_OBJECT_HANDLE::default();
        let secret_class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
        let generic_type: CK_KEY_TYPE = CKK_GENERIC_SECRET;
        let value_len: CK_ULONG = 32;
        let ck_false = CK_FALSE;
        let ck_true = CK_TRUE;
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_ML_KEM,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut secret_template = Self::mlkem_secret_template(
            &secret_class,
            &generic_type,
            &value_len,
            &ck_false,
            &ck_true,
        )?;
        let hsm = self.hsm();
        let decapsulate = hsm.C_DecapsulateKey.ok_or_else(|| {
            HError::Default("C_DecapsulateKey not available on library".to_owned())
        })?;

        #[expect(unsafe_code)]
        let rv = unsafe {
            decapsulate(
                self.session_handle(),
                &raw mut mechanism,
                private_key_handle,
                secret_template.as_mut_ptr(),
                CK_ULONG::try_from(secret_template.len())?,
                ciphertext.as_mut_ptr(),
                CK_ULONG::try_from(ciphertext.len())?,
                &raw mut secret_handle,
            )
        };
        if rv != CKR_OK {
            return Err(HError::Default(format!(
                "Failed ML-KEM decapsulation. Return code: {rv}"
            )));
        }
        let shared_secret = self.read_secret_value(secret_handle)?;
        self.destroy_object(secret_handle)?;
        Ok(Zeroizing::new(shared_secret))
    }

    pub fn mldsa_verify(
        &self,
        public_key_handle: CK_OBJECT_HANDLE,
        data: &[u8],
        signature: &[u8],
    ) -> HResult<bool> {
        let mut data = data.to_vec();
        let mut signature = signature.to_vec();
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_ML_DSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        hsm_call!(
            self.hsm(),
            "Failed to initialize signature verification",
            C_VerifyInit,
            self.session_handle(),
            &raw mut mechanism,
            public_key_handle
        );

        #[expect(unsafe_code)]
        let rv = unsafe {
            self.hsm()
                .C_Verify
                .ok_or_else(|| HError::Default("C_Verify not available on library".to_owned()))?(
                self.session_handle(),
                data.as_mut_ptr(),
                CK_ULONG::try_from(data.len())?,
                signature.as_mut_ptr(),
                CK_ULONG::try_from(signature.len())?,
            )
        };
        match rv {
            CKR_OK => Ok(true),
            CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE => Ok(false),
            rv => Err(HError::Default(format!(
                "Failed to verify signature. Return code: {rv}"
            ))),
        }
    }

    fn read_pqc_parameter_set(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        attribute_type: CK_ATTRIBUTE_TYPE,
    ) -> HResult<CK_ULONG> {
        let mut parameter_set = CK_ULONG::default();
        let mut template = [CK_ATTRIBUTE {
            type_: attribute_type,
            pValue: (&raw mut parameter_set).cast::<std::ffi::c_void>(),
            ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
        }];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Err(HError::Default("PQC key not found".to_owned()));
        }
        Ok(parameter_set)
    }

    fn read_secret_value(&self, secret_handle: CK_OBJECT_HANDLE) -> HResult<Vec<u8>> {
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        }];
        if self
            .call_get_attributes(secret_handle, &mut template)?
            .is_none()
        {
            return Err(HError::Default("ML-KEM secret handle not found".to_owned()));
        }
        let value_len = template[0].ulValueLen;
        let mut value = vec![0_u8; usize::try_from(value_len)?];
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: value.as_mut_ptr().cast::<std::ffi::c_void>(),
            ulValueLen: value_len,
        }];
        if self
            .call_get_attributes(secret_handle, &mut template)?
            .is_none()
        {
            return Err(HError::Default("ML-KEM secret handle not found".to_owned()));
        }
        Ok(value)
    }

    fn mlkem_secret_template(
        secret_class: &CK_OBJECT_CLASS,
        generic_type: &CK_KEY_TYPE,
        value_len: &CK_ULONG,
        ck_false: &CK_BBOOL,
        ck_true: &CK_BBOOL,
    ) -> HResult<Vec<CK_ATTRIBUTE>> {
        Ok(vec![
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: std::ptr::from_ref(secret_class)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(generic_type)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(ck_false)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: std::ptr::from_ref(ck_false)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: std::ptr::from_ref(ck_false)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXTRACTABLE,
                pValue: std::ptr::from_ref(ck_true)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE_LEN,
                pValue: std::ptr::from_ref(value_len)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
        ])
    }
}
