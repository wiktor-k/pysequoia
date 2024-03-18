use openpgp::parse::Parse;
use openpgp::{parse::stream::*, policy::StandardPolicy};
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::Decrypted;

#[pyfunction]
pub fn verify(bytes: &[u8], store: Py<PyAny>) -> PyResult<Decrypted> {
    let helper = PyVerifier { store };

    let policy = &StandardPolicy::new();

    let mut verifier = VerifierBuilder::from_bytes(&bytes)?.with_policy(policy, None, helper)?;

    let mut sink = vec![];
    std::io::copy(&mut verifier, &mut sink)?;

    Ok(Decrypted { content: sink })
}

struct PyVerifier {
    store: Py<PyAny>,
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
        let mut good = false;
        for (i, layer) in structure.into_iter().enumerate() {
            match (i, layer) {
                (0, MessageLayer::SignatureGroup { results }) => match results.into_iter().next() {
                    Some(Ok(_)) => good = true,
                    Some(Err(e)) => return Err(openpgp::Error::from(e).into()),
                    None => return Err(anyhow::anyhow!("No signature")),
                },
                _ => return Err(anyhow::anyhow!("Unexpected message structure")),
            }
        }

        if good {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Signature verification failed"))
        }
    }
}
