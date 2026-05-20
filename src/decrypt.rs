use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use pyo3::prelude::*;
use sequoia_openpgp::crypto::{Decryptor, Password, SessionKey};
use sequoia_openpgp::packet::{PKESK, SKESK};
use sequoia_openpgp::parse::{Parse, stream::*};
use sequoia_openpgp::policy::StandardPolicy as P;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{KeyHandle, cert};

use crate::verify::PyVerifier;
use crate::{Decrypted, ValidSig};

/// A decryption helper that holds the key material needed to decrypt messages.
///
/// Obtain a `PyDecryptor` via `Tsk.decryptor()`.
#[pyclass(from_py_object)]
#[derive(Clone, Default)]
pub struct PyDecryptor {
    inner: Option<Arc<Mutex<Box<dyn Decryptor + Send + Sync + 'static>>>>,
    verifier: Option<PyVerifier>,
    passwords: Vec<Password>,
}

impl PyDecryptor {
    pub fn new(inner: Box<dyn Decryptor + Send + Sync + 'static>) -> Self {
        Self {
            inner: Some(Arc::new(Mutex::new(inner))),
            verifier: None,
            passwords: Vec::new(),
        }
    }

    pub fn set_verifier(&mut self, verifier: impl Into<Option<PyVerifier>>) {
        self.verifier = verifier.into();
    }

    pub fn set_passwords(&mut self, passwords: Vec<String>) {
        self.passwords = passwords.into_iter().map(Into::into).collect();
    }

    pub fn valid_sigs(self) -> Vec<ValidSig> {
        if let Some(verifier) = self.verifier {
            verifier.valid_sigs()
        } else {
            vec![]
        }
    }
}

/// Decrypt an OpenPGP message from bytes.
///
/// Provide either a `decryptor` (from a secret key) or `passwords` for password-based decryption.
/// Optionally provide a `store` callback for signature verification during decryption.
#[pyfunction]
#[pyo3(signature = (bytes, decryptor=None, store=None, passwords=vec![]))]
pub fn decrypt(
    bytes: &[u8],
    decryptor: Option<PyDecryptor>,
    store: Option<Py<PyAny>>,
    passwords: Vec<String>,
) -> PyResult<Decrypted> {
    if decryptor.is_none() && passwords.is_empty() {
        return Err(anyhow::anyhow!(
            "Either `decryptor` or `passwords` parameter should be given and non-empty."
        )
        .into());
    }
    let mut decryptor = decryptor.unwrap_or_default();
    decryptor.set_passwords(passwords);
    if let Some(store) = store {
        decryptor.set_verifier(PyVerifier::from_callback(store));
    }

    let policy = &P::new();

    let mut decryptor =
        DecryptorBuilder::from_bytes(bytes)?.with_policy(policy, None, decryptor)?;

    let mut sink = Vec::new();
    std::io::copy(&mut decryptor, &mut sink)?;
    let decryptor = decryptor.into_helper();
    Ok(Decrypted {
        content: Some(sink),
        valid_sigs: decryptor.valid_sigs(),
    })
}

/// Decrypt an OpenPGP message from a file, writing the plaintext to another file.
///
/// Provide either a `decryptor` (from a secret key) or `passwords` for password-based decryption.
/// Optionally provide a `store` callback for signature verification during decryption.
#[pyfunction]
#[pyo3(signature = (input, output, decryptor=None, store=None, passwords=vec![]))]
pub fn decrypt_file(
    input: PathBuf,
    output: PathBuf,
    decryptor: Option<PyDecryptor>,
    store: Option<Py<PyAny>>,
    passwords: Vec<String>,
) -> PyResult<Decrypted> {
    if decryptor.is_none() && passwords.is_empty() {
        return Err(anyhow::anyhow!(
            "Either `decryptor` or `passwords` parameter should be given and non-empty."
        )
        .into());
    }
    let mut decryptor = decryptor.unwrap_or_default();
    decryptor.set_passwords(passwords);
    if let Some(store) = store {
        decryptor.set_verifier(PyVerifier::from_callback(store));
    }
    let policy = &P::new();

    let mut decryptor = DecryptorBuilder::from_file(&input)
        .context("Failed to open input file")?
        .with_policy(policy, None, decryptor)?;

    let mut sink = std::fs::File::create(&output).context("Failed to create output file")?;
    std::io::copy(&mut decryptor, &mut sink)?;
    let decryptor = decryptor.into_helper();
    Ok(Decrypted {
        content: None,
        valid_sigs: decryptor.valid_sigs(),
    })
}

impl VerificationHelper for PyDecryptor {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<cert::Cert>> {
        if let Some(verifier) = &mut self.verifier {
            verifier.get_certs(ids)
        } else {
            Ok(vec![])
        }
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        if let Some(verifier) = &mut self.verifier {
            verifier.check(structure)
        } else {
            Ok(())
        }
    }
}

impl DecryptionHelper for PyDecryptor {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> sequoia_openpgp::Result<Option<cert::Cert>> {
        for skesk in skesks.iter() {
            for password in self.passwords.iter() {
                if let Ok((algo, session_key)) = skesk.decrypt(password)
                    && decrypt(algo, &session_key)
                {
                    return Ok(None);
                }
            }
        }

        if let Some(inner) = &mut self.inner {
            let pair = &mut *inner.lock().unwrap();

            for pkesk in pkesks.iter() {
                if pkesk
                    .decrypt(pair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key))
                    .is_some()
                {
                    return Ok(None);
                }
            }
        }

        Err(anyhow::anyhow!("No key to decrypt message"))
    }
}
