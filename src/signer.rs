use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

#[pyclass]
#[derive(Clone)]
pub struct PySigner {
    inner: Arc<Mutex<Box<dyn openpgp::crypto::Signer + Send + Sync + 'static>>>,
    public: openpgp::packet::Key<
        openpgp::packet::key::PublicParts,
        openpgp::packet::key::UnspecifiedRole,
    >,
}

impl PySigner {
    pub fn new(inner: Box<dyn openpgp::crypto::Signer + Send + Sync + 'static>) -> Self {
        let public = inner.public().clone();
        Self {
            inner: Arc::new(Mutex::new(inner)),
            public,
        }
    }
}

impl openpgp::crypto::Signer for PySigner {
    fn public(
        &self,
    ) -> &openpgp::packet::Key<
        openpgp::packet::key::PublicParts,
        openpgp::packet::key::UnspecifiedRole,
    > {
        &self.public
    }

    fn sign(
        &mut self,
        hash_algo: openpgp::types::HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<openpgp::crypto::mpi::Signature> {
        self.inner.lock().unwrap().sign(hash_algo, digest)
    }
}
