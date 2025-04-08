use std::borrow::Cow;
use std::io::Write;

use pyo3::prelude::*;
use sequoia_openpgp::armor;
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::stream::{LiteralWriter, Message};

use crate::signer::PySigner;

#[pyclass(eq, eq_int)]
#[derive(PartialEq)]
pub enum SignatureMode {
    #[pyo3(name = "INLINE")]
    Inline,
    #[pyo3(name = "DETACHED")]
    Detached,
    #[pyo3(name = "CLEAR")]
    Clear,
}

#[pyfunction]
#[pyo3(signature = (signer, bytes, *, mode=&SignatureMode::Inline))]
pub fn sign(signer: PySigner, bytes: &[u8], mode: &SignatureMode) -> PyResult<Cow<'static, [u8]>> {
    use sequoia_openpgp::serialize::stream::Signer;

    let mut sink = vec![];
    {
        let message = Message::new(&mut sink);
        let message = if mode == &SignatureMode::Inline {
            Armorer::new(message).kind(armor::Kind::Message).build()?
        } else if mode == &SignatureMode::Detached {
            Armorer::new(message).kind(armor::Kind::Signature).build()?
        } else {
            message
        };
        let message = Signer::new(message, signer)?;
        let mut message = if mode == &SignatureMode::Inline {
            LiteralWriter::new(message.build()?).build()?
        } else if mode == &SignatureMode::Detached {
            message.detached().build()?
        } else {
            message.cleartext().build()?
        };
        message.write_all(bytes)?;
        message.finalize()?;
    }

    Ok(sink.into())
}
