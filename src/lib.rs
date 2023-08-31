use openpgp::serialize::stream::Armorer;
use pyo3::prelude::*;

mod card;
mod cert;
mod decrypt;
mod encrypt;
mod notation;
mod sign;
mod signature;
mod signer;
mod store;
mod user_id;

use openpgp::armor::Kind;
use openpgp::packet::Packet;
use openpgp::serialize::{stream::Message, Marshal};
use sequoia_openpgp as openpgp;

pub(crate) fn serialize<T>(p: Packet, armor_kind: T) -> openpgp::Result<Vec<u8>>
where
    T: Into<Option<Kind>>,
{
    let mut sink = vec![];
    let mut message = Message::new(&mut sink);
    if let Some(kind) = armor_kind.into() {
        message = Armorer::new(message).kind(kind).build()?
    }
    p.serialize(&mut message)?;
    message.finalize()?;
    Ok(sink)
}

#[pymodule]
fn pysequoia(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<cert::Cert>()?;
    m.add_class::<store::Store>()?;
    m.add_class::<card::Card>()?;
    m.add_class::<notation::Notation>()?;
    m.add_function(wrap_pyfunction!(sign::sign, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt::encrypt, m)?)?;
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
