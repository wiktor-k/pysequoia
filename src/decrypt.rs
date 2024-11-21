use std::sync::{Arc, Mutex};

use openpgp::crypto::SessionKey;
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::StandardPolicy as P;
use openpgp::types::SymmetricAlgorithm;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::verify::PyVerifier;
use crate::{Decrypted, ValidSig};

#[pyclass]
#[derive(Clone)]
pub struct PyDecryptor {
    inner: Arc<Mutex<Box<dyn openpgp::crypto::Decryptor + Send + Sync + 'static>>>,
    verifier: Option<PyVerifier>,
}

impl PyDecryptor {
    pub fn new(inner: Box<dyn openpgp::crypto::Decryptor + Send + Sync + 'static>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            verifier: None,
        }
    }

    pub fn set_verifier(&mut self, verifier: impl Into<Option<PyVerifier>>) {
        self.verifier = verifier.into();
    }

    pub fn valid_sigs(self) -> Vec<ValidSig> {
        if let Some(verifier) = self.verifier {
            verifier.valid_sigs()
        } else {
            vec![]
        }
    }
}

#[pyfunction]
#[pyo3(signature = (decryptor, bytes, store=None))]
pub fn decrypt(
    mut decryptor: PyDecryptor,
    bytes: &[u8],
    store: Option<Py<PyAny>>,
) -> PyResult<Decrypted> {
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
        content: sink,
        valid_sigs: decryptor.valid_sigs(),
    })
}

impl VerificationHelper for PyDecryptor {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        if let Some(verifier) = &mut self.verifier {
            verifier.get_certs(ids)
        } else {
            Ok(vec![])
        }
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        if let Some(verifier) = &mut self.verifier {
            verifier.check(structure)
        } else {
            Ok(())
        }
    }
}

impl DecryptionHelper for PyDecryptor {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let pair = &mut *self.inner.lock().unwrap();

        for pkesk in pkesks.iter() {
            if pkesk
                .decrypt(pair, sym_algo)
                .map(|(algo, session_key)| decrypt(algo, &session_key))
                .is_some()
            {
                return Ok(None);
            }
        }

        Err(anyhow::anyhow!("No key to decrypt message"))
    }
}
