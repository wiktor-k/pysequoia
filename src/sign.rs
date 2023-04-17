use std::borrow::Cow;
use std::io::Write;

use openpgp::serialize::stream::Armorer;
use openpgp::serialize::stream::{LiteralWriter, Message};
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::signer::PySigner;

#[pyfunction]
pub fn sign(signer: PySigner, bytes: &[u8]) -> PyResult<Cow<'static, [u8]>> {
    use openpgp::serialize::stream::Signer;

    let mut sink = vec![];
    {
        let message = Message::new(&mut sink);

        let message = Armorer::new(message)
            .kind(openpgp::armor::Kind::Signature)
            .build()?;
        let message = Signer::new(message, signer).build()?;

        let mut message = LiteralWriter::new(message).build()?;

        message.write_all(bytes)?;

        message.finalize()?;
    }

    Ok(sink.into())
}
