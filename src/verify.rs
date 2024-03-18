use openpgp::parse::Parse;
use openpgp::{parse::stream::*, policy::StandardPolicy};
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::{Decrypted, ValidSig};

#[pyfunction]
pub fn verify(bytes: &[u8], store: Py<PyAny>) -> PyResult<Decrypted> {
    let helper = PyVerifier::from_callback(store);

    let policy = &StandardPolicy::new();

    let mut verifier = VerifierBuilder::from_bytes(&bytes)?.with_policy(policy, None, helper)?;

    let mut sink = vec![];
    std::io::copy(&mut verifier, &mut sink)?;

    let helper = verifier.into_helper();

    Ok(Decrypted {
        content: sink,
        valid_sigs: helper.valid_sigs,
    })
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
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        let mut certs = vec![];
        let result: Vec<crate::cert::Cert> = Python::with_gil(|py| {
            let str_ids = ids
                .iter()
                .map(|key_id| format!("{:x}", key_id))
                .collect::<Vec<_>>();
            self.store.call1(py, (str_ids,))?.extract(py)
        })?;
        for cert in result.into_iter() {
            certs.push(cert.cert().clone());
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
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
            Err(anyhow::anyhow!("Signature verification failed"))
        }
    }
}
