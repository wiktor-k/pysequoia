use std::io::Write;

use openpgp::serialize::stream::Armorer;
use openpgp::serialize::stream::{LiteralWriter, Message};
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::signer::PySigner;

#[pyfunction]
pub fn sign(signer: PySigner, data: String) -> PyResult<String> {
    use openpgp::serialize::stream::Signer;

    let mut sink = vec![];
    {
        let message = Message::new(&mut sink);

        let message = Armorer::new(message)
            .kind(openpgp::armor::Kind::Signature)
            .build()?;
        let message = Signer::new(message, signer).build()?;

        let mut message = LiteralWriter::new(message).build()?;

        message.write_all(data.as_bytes())?;

        message.finalize()?;
    }

    Ok(String::from_utf8_lossy(&sink).into())
}
