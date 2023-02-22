use std::sync::{Arc, Mutex};

use openpgp::crypto::SessionKey;
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::StandardPolicy as P;
use openpgp::types::SymmetricAlgorithm;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

#[pyclass]
#[derive(Clone)]
pub struct PyDecryptor {
    inner: Arc<Mutex<Box<dyn openpgp::crypto::Decryptor + Send + Sync + 'static>>>,
}

impl PyDecryptor {
    pub fn new(inner: Box<dyn openpgp::crypto::Decryptor + Send + Sync + 'static>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct Decrypted {
    content: Vec<u8>,
}

#[pymethods]
impl Decrypted {
    #[getter]
    pub fn content(&self) -> String {
        String::from_utf8_lossy(&self.content).into()
    }
}

#[pyfunction]
pub fn decrypt(decryptor: PyDecryptor, data: String) -> PyResult<Decrypted> {
    let policy = &P::new();

    let mut decryptor =
        DecryptorBuilder::from_bytes(&data)?.with_policy(policy, None, decryptor)?;

    let mut sink = Vec::new();
    std::io::copy(&mut decryptor, &mut sink)?;
    Ok(Decrypted { content: sink })
}

impl VerificationHelper for PyDecryptor {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
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
