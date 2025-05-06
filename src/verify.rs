use std::path::PathBuf;

use anyhow::anyhow;
use pyo3::prelude::*;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::{cert, parse::stream::*, policy::StandardPolicy};

use crate::signature::Sig;
use crate::{Decrypted, ValidSig};

enum SignedData<'a> {
    File(PathBuf),
    Bytes(&'a [u8]),
}

impl From<SignedData<'_>> for Option<Vec<u8>> {
    fn from(value: SignedData) -> Self {
        match value {
            SignedData::File(_) => None,
            SignedData::Bytes(bytes) => Some(bytes.into()),
        }
    }
}

#[pyfunction]
#[pyo3(signature = (bytes=None, store=None, file=None, signature=None))]
pub fn verify(
    bytes: Option<&[u8]>,
    store: Option<Py<PyAny>>,
    #[allow(unused)] file: Option<PathBuf>,
    signature: Option<&Sig>,
) -> PyResult<Decrypted> {
    let Some(store) = store else {
        return Err(anyhow!("Store parameter is required").into());
    };
    let signed_data = if let Some(bytes) = bytes {
        if file.is_some() {
            return Err(anyhow!("Cannot set both `bytes` or `file` parameters.").into());
        }
        SignedData::Bytes(bytes)
    } else if let Some(file) = file {
        SignedData::File(file)
    } else {
        return Err(anyhow!("Either `bytes` or `file` parameter should be given.").into());
    };

    let helper = PyVerifier::from_callback(store);

    let policy = &StandardPolicy::new();

    if let Some(signature) = signature {
        // detached signature verification
        let bytes = signature.__bytes__()?;
        let mut verifier =
            DetachedVerifierBuilder::from_bytes(&bytes)?.with_policy(policy, None, helper)?;

        match &signed_data {
            SignedData::File(path) => verifier.verify_file(path)?,
            SignedData::Bytes(bytes) => verifier.verify_bytes(bytes)?,
        };

        let helper = verifier.into_helper();

        Ok(Decrypted {
            content: signed_data.into(),
            valid_sigs: helper.valid_sigs,
        })
    } else {
        // inline signature verification
        let mut verifier = match &signed_data {
            SignedData::File(path) => VerifierBuilder::from_file(path)?,
            SignedData::Bytes(bytes) => VerifierBuilder::from_bytes(bytes)?,
        }
        .with_policy(policy, None, helper)?;

        let mut sink = vec![];
        std::io::copy(&mut verifier, &mut sink)?;

        let helper = verifier.into_helper();

        Ok(Decrypted {
            content: Some(sink),
            valid_sigs: helper.valid_sigs,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PyVerifier {
    store: Py<PyAny>,
    valid_sigs: Vec<ValidSig>,
}

impl PyVerifier {
    pub fn from_callback(store: Py<PyAny>) -> Self {
        Self {
            store,
            valid_sigs: vec![],
        }
    }

    pub fn valid_sigs(self) -> Vec<ValidSig> {
        self.valid_sigs
    }
}

impl VerificationHelper for PyVerifier {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<cert::Cert>> {
        let mut certs = vec![];
        let result: Vec<crate::cert::Cert> = Python::with_gil(|py| {
            let str_ids = ids
                .iter()
                .map(|key_id| format!("{key_id:x}"))
                .collect::<Vec<_>>();
            self.store.call1(py, (str_ids,))?.extract(py)
        })?;
        for cert in result.into_iter() {
            certs.push(cert.cert().clone());
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        let mut valid_sigs = vec![];
        for (i, layer) in structure.into_iter().enumerate() {
            match layer {
                MessageLayer::Encryption { .. } if i == 0 => (),
                MessageLayer::Compression { .. } if i == 1 => (),
                MessageLayer::SignatureGroup { results } if (0..2).contains(&i) => {
                    for result in results.into_iter().flatten() {
                        valid_sigs.push(result.into());
                    }
                }
                _ => return Err(anyhow::anyhow!("Unexpected message structure")),
            }
        }

        self.valid_sigs = valid_sigs;

        if !self.valid_sigs.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Signature verification failed: no valid signatures found."
            ))
        }
    }
}
