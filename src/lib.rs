use pyo3::prelude::*;

mod card;
mod cert;
mod decrypt;
mod ks;
mod signer;
mod store;
mod utils;
mod wkd;

#[pymodule]
fn pysequoia(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<cert::Cert>()?;
    m.add_class::<ks::KeyServer>()?;
    m.add_class::<wkd::WKD>()?;
    m.add_class::<store::Store>()?;
    m.add_class::<card::Card>()?;
    m.add_function(wrap_pyfunction!(utils::sign, m)?)?;
    m.add_function(wrap_pyfunction!(utils::encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt::decrypt, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use openpgp::cert::prelude::*;
    use sequoia_openpgp as openpgp;
    use sequoia_openpgp::serialize::SerializeInto;
    use testresult::TestResult;

    #[test]
    fn test_armoring() -> TestResult {
        let cert = CertBuilder::general_purpose(None, Some("test@example.com"))
            .generate()?
            .0;
        assert!(cert.armored().to_vec().is_ok());
        Ok(())
    }
}
