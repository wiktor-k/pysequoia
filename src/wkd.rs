use pyo3::prelude::*;

use crate::cert::Cert;

#[allow(clippy::upper_case_acronyms)]
#[pyclass]
pub struct WKD;

#[pymethods]
impl WKD {
    #[staticmethod]
    fn search(py: Python<'_>, email: String) -> PyResult<&PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let certs = sequoia_net::wkd::get(email).await?;
            if let Some(cert) = certs.first() {
                let cert: Cert = cert.clone().into();
                Ok(Some(cert))
            } else {
                Ok(None)
            }
        })
    }
}
