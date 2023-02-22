use openpgp_card_pcsc::PcscBackend;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::decrypt;
use crate::signer::PySigner;

#[pyclass]
pub struct Card {
    open: openpgp_card_sequoia::Card<openpgp_card_sequoia::state::Open>,
}

#[pymethods]
impl Card {
    #[staticmethod]
    pub fn open(ident: &str) -> anyhow::Result<Self> {
        Ok(Self {
            open: PcscBackend::open_by_ident(ident, None)?.into(),
        })
    }

    #[getter]
    pub fn cardholder(&mut self) -> anyhow::Result<Option<String>> {
        let mut transaction = self.open.transaction()?;
        Ok(transaction.cardholder_name()?)
    }

    #[getter]
    pub fn ident(&mut self) -> anyhow::Result<String> {
        let transaction = self.open.transaction()?;
        Ok(transaction.application_identifier()?.ident())
    }

    #[staticmethod]
    pub fn all() -> anyhow::Result<Vec<Card>> {
        Ok(PcscBackend::cards(None)?
            .into_iter()
            .map(|card| Self { open: card.into() })
            .collect())
    }

    pub fn signer(&mut self, pin: String) -> anyhow::Result<PySigner> {
        use sequoia_openpgp::crypto::Signer;

        struct CardSigner {
            public: openpgp::packet::Key<
                openpgp::packet::key::PublicParts,
                openpgp::packet::key::UnspecifiedRole,
            >,
            ident: String,
            pin: String,
        }

        impl openpgp::crypto::Signer for CardSigner {
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
                let backend = openpgp_card_pcsc::PcscBackend::open_by_ident(&self.ident, None)?;
                let mut card: openpgp_card_sequoia::Card<openpgp_card_sequoia::state::Open> =
                    backend.into();
                let mut transaction = card.transaction()?;

                transaction.verify_user_for_signing(self.pin.as_bytes())?;
                let mut user = transaction.signing_card().expect("This should not fail");

                let mut signer = user.signer(&|| {})?;
                signer.sign(hash_algo, digest)
            }
        }

        let public = {
            let mut transaction = self.open.transaction()?;

            transaction.verify_user_for_signing(pin.as_bytes())?;

            let mut user = transaction.signing_card().expect("This should not fail");

            let signer = user.signer(&|| {})?;
            signer.public().clone()
        };
        Ok(PySigner::new(Box::new(CardSigner {
            public,
            ident: self.ident()?,
            pin,
        })))
    }

    pub fn decryptor(&mut self, pin: String) -> anyhow::Result<decrypt::PyDecryptor> {
        use sequoia_openpgp::crypto::Decryptor;

        struct CardDecryptor {
            public: openpgp::packet::Key<
                openpgp::packet::key::PublicParts,
                openpgp::packet::key::UnspecifiedRole,
            >,
            ident: String,
            pin: String,
        }

        impl openpgp::crypto::Decryptor for CardDecryptor {
            fn public(
                &self,
            ) -> &openpgp::packet::Key<
                openpgp::packet::key::PublicParts,
                openpgp::packet::key::UnspecifiedRole,
            > {
                &self.public
            }
            fn decrypt(
                &mut self,
                ciphertext: &openpgp::crypto::mpi::Ciphertext,
                plaintext_len: Option<usize>,
            ) -> openpgp::Result<openpgp::crypto::SessionKey> {
                let backend = openpgp_card_pcsc::PcscBackend::open_by_ident(&self.ident, None)?;
                let mut card: openpgp_card_sequoia::Card<openpgp_card_sequoia::state::Open> =
                    backend.into();
                let mut transaction = card.transaction()?;

                transaction.verify_user(self.pin.as_bytes())?;
                let mut user = transaction.user_card().expect("user_card should not fail");

                let mut decryptor = user.decryptor(&|| {})?;
                decryptor.decrypt(ciphertext, plaintext_len)
            }
        }

        let public = {
            let mut transaction = self.open.transaction()?;

            transaction.verify_user_for_signing(pin.as_bytes())?;

            let mut user = transaction.user_card().expect("user_card should not fail");

            let decryptor = user.decryptor(&|| {})?;
            decryptor.public().clone()
        };
        Ok(decrypt::PyDecryptor::new(Box::new(CardDecryptor {
            public,
            ident: self.ident()?,
            pin,
        })))
    }

    pub fn __repr__(&mut self) -> anyhow::Result<String> {
        Ok(format!("<Card ident={}>", self.ident()?))
    }
}
