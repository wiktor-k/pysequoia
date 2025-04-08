use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use sequoia_openpgp::{crypto, packet, types};

#[pyclass]
#[derive(Clone)]
pub struct PySigner {
    inner: Arc<Mutex<Box<dyn crypto::Signer + Send + Sync + 'static>>>,
    public: packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole>,
}

impl PySigner {
    pub fn new(inner: Box<dyn crypto::Signer + Send + Sync + 'static>) -> Self {
        let public = inner.public().clone();
        Self {
            inner: Arc::new(Mutex::new(inner)),
            public,
        }
    }
}

impl crypto::Signer for PySigner {
    fn public(&self) -> &packet::Key<packet::key::PublicParts, packet::key::UnspecifiedRole> {
        &self.public
    }

    fn sign(
        &mut self,
        hash_algo: types::HashAlgorithm,
        digest: &[u8],
    ) -> sequoia_openpgp::Result<crypto::mpi::Signature> {
        self.inner.lock().unwrap().sign(hash_algo, digest)
    }
}
