use pyo3::prelude::*;

use crate::cert::Cert;

#[allow(clippy::upper_case_acronyms)]
#[pyclass]
pub struct WKD;

#[pymethods]
impl WKD {
    #[staticmethod]
    fn search(py: Python<'_>, email: String) -> PyResult<&PyAny> {
        /*pyo3_asyncio::tokio::future_into_py(py, async move {
            let certs = sequoia_net::wkd::get(email).await?;
            Ok(certs.into_iter().map(Into::into).collect::<Vec<Cert>>())
    })*/
        unimplemented!()
    }
}
