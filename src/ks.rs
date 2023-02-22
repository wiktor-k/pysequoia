use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::cert::Cert;

#[pyclass]
pub struct KeyServer {
    uri: String,
}

#[pymethods]
impl KeyServer {
    #[new]
    pub fn new(uri: &str) -> Self {
        Self { uri: uri.into() }
    }

    #[allow(clippy::should_implement_trait)]
    #[staticmethod]
    pub fn default() -> Self {
        Self {
            uri: "hkps://keys.openpgp.org".into(),
        }
    }

    pub fn get<'a>(&self, py: Python<'a>, fpr: String) -> PyResult<&'a PyAny> {
        let uri: String = self.uri.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            use openpgp::Fingerprint;
            let fpr: Fingerprint = fpr.parse()?;
            let mut ks = sequoia_net::KeyServer::new(sequoia_net::Policy::Encrypted, &uri)?;
            let cert = ks.get(fpr);
            let cert: Cert = cert.await?.into();
            Ok(cert)
        })
    }

    pub fn __repr__(&self) -> String {
        format!("<KeyServer uri={}>", self.uri)
    }
}
