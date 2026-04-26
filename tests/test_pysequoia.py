import os
import tempfile
from datetime import datetime

import pytest

from pysequoia import (
    ArmorKind,
    Cert,
    Notation,
    Profile,
    Sig,
    SignatureMode,
    armor,
    decrypt,
    decrypt_file,
    encrypt,
    encrypt_file,
    sign,
    sign_file,
    verify,
)
from pysequoia.packet import PacketPile, SignatureType, Tag

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_path(name):
    return os.path.join(FIXTURES, name)


@pytest.fixture
def signing_key():
    return Cert.from_file(fixture_path("signing-key.asc"))


@pytest.fixture
def wiktor_key():
    return Cert.from_file(fixture_path("wiktor.asc"))


@pytest.fixture
def wiktor_fresh_key():
    return Cert.from_file(fixture_path("wiktor-fresh.asc"))


class TestSign:
    def test_inline(self, signing_key):
        signed = sign(signing_key.secrets.signer(), b"data to be signed")
        assert "PGP MESSAGE" in str(signed)

    def test_detached(self, signing_key):
        detached = sign(
            signing_key.secrets.signer(),
            b"data to be signed",
            mode=SignatureMode.DETACHED,
        )
        assert "PGP SIGNATURE" in str(detached)

    def test_clear(self, signing_key):
        clear = sign(
            signing_key.secrets.signer(),
            b"data to be signed",
            mode=SignatureMode.CLEAR,
        )
        assert "PGP SIGNED MESSAGE" in str(clear)


class TestSignFile:
    def test_inline_file(self, signing_key):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"data to be signed")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as out:
            output_path = out.name

        try:
            sign_file(signing_key.secrets.signer(), input_path, output_path)
            assert b"PGP MESSAGE" in open(output_path, "rb").read()
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_detached_file(self, signing_key):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"data to be signed")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as out:
            detached_path = out.name

        try:
            sign_file(
                signing_key.secrets.signer(),
                input_path,
                detached_path,
                mode=SignatureMode.DETACHED,
            )
            assert b"PGP SIGNATURE" in open(detached_path, "rb").read()
        finally:
            os.unlink(input_path)
            os.unlink(detached_path)


SIGNING_KEY_FPR = "afcf5405e8f49dbcd5dc548a86375b854b86acf9"


class TestVerify:
    def _store(self, signing_key):
        def get_certs(key_ids):
            return [signing_key]
        return get_certs

    def test_inline_verify(self, signing_key):
        signed = sign(signing_key.secrets.signer(), b"data to be signed")
        result = verify(signed, self._store(signing_key))
        assert result.bytes.decode("utf8") == "data to be signed"
        assert result.valid_sigs[0].certificate == SIGNING_KEY_FPR
        assert result.valid_sigs[0].signing_key == SIGNING_KEY_FPR

    def test_detached_verify_bytes(self, signing_key):
        data = b"data to be signed"
        detached = sign(
            signing_key.secrets.signer(), data, mode=SignatureMode.DETACHED
        )
        signature = Sig.from_bytes(detached)
        result = verify(bytes=data, store=self._store(signing_key), signature=signature)
        assert result.valid_sigs[0].certificate == SIGNING_KEY_FPR
        assert result.valid_sigs[0].signing_key == SIGNING_KEY_FPR

    def test_detached_verify_file(self, signing_key):
        data = b"data to be signed"
        detached = sign(
            signing_key.secrets.signer(), data, mode=SignatureMode.DETACHED
        )
        signature = Sig.from_bytes(detached)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp.close()

            try:
                result = verify(
                    file=tmp.name,
                    store=self._store(signing_key),
                    signature=signature,
                )
                assert result.valid_sigs[0].certificate == SIGNING_KEY_FPR
                assert result.valid_sigs[0].signing_key == SIGNING_KEY_FPR
            finally:
                os.unlink(tmp.name)


class TestEncryptDecrypt:
    def test_encrypt_decrypt_no_signature(self):
        sender = Cert.generate("Sender <sender@example.com>")
        receiver = Cert.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(recipients=[receiver], bytes=content.encode("utf8"))
        decrypted = decrypt(
            decryptor=receiver.secrets.decryptor(), bytes=encrypted
        )

        assert decrypted.bytes.decode("utf8") == content
        assert len(decrypted.valid_sigs) == 0

    def test_encrypt_decrypt_with_signature(self):
        sender = Cert.generate("Sender <sender@example.com>")
        receiver = Cert.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(
            signer=sender.secrets.signer(),
            recipients=[receiver],
            bytes=content.encode("utf8"),
        )

        def store(key_ids):
            return [sender]

        decrypted = decrypt(
            decryptor=receiver.secrets.decryptor(),
            bytes=encrypted,
            store=store,
        )

        assert decrypted.bytes.decode("utf8") == content
        assert decrypted.valid_sigs[0].certificate == sender.fingerprint

    def test_symmetric_encrypt_decrypt(self):
        content = "content to encrypt"
        encrypted = encrypt(passwords=["sekrit"], bytes=content.encode("utf8"))
        decrypted = decrypt(passwords=["sekrit"], bytes=encrypted)
        assert decrypted.bytes.decode("utf8") == content


class TestEncryptDecryptFile:
    def test_encrypt_file(self):
        sender = Cert.generate("Sender <sender@example.com>")
        receiver = Cert.generate("Receiver <receiver@example.com>")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"content to encrypt")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as out:
            output_path = out.name

        try:
            encrypt_file(
                signer=sender.secrets.signer(),
                recipients=[receiver],
                input=input_path,
                output=output_path,
            )
            assert b"PGP MESSAGE" in open(output_path, "rb").read()
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_decrypt_file_no_signature(self):
        receiver = Cert.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(recipients=[receiver], bytes=content.encode("utf8"))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as inp:
            inp.write(encrypted)
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as out:
            output_path = out.name

        try:
            decrypted = decrypt_file(
                decryptor=receiver.secrets.decryptor(),
                input=input_path,
                output=output_path,
            )
            assert decrypted.bytes is None
            assert open(output_path, "rb").read().decode("utf8") == content
            assert len(decrypted.valid_sigs) == 0
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_decrypt_file_with_signature(self):
        sender = Cert.generate("Sender <sender@example.com>")
        receiver = Cert.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(
            signer=sender.secrets.signer(),
            recipients=[receiver],
            bytes=content.encode("utf8"),
        )

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as inp:
            inp.write(encrypted)
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as out:
            output_path = out.name

        def store(key_ids):
            return [sender]

        try:
            decrypted = decrypt_file(
                decryptor=receiver.secrets.decryptor(),
                input=input_path,
                output=output_path,
                store=store,
            )
            assert open(output_path, "rb").read().decode("utf8") == content
            assert decrypted.valid_sigs[0].certificate == sender.fingerprint
        finally:
            os.unlink(input_path)
            os.unlink(output_path)


class TestCert:
    def test_generate_and_export(self):
        cert = Cert.generate("Test <test@example.com>")
        assert len(str(cert)) > 0
        assert len(bytes(cert)) > 0

    def test_secrets_export(self):
        cert = Cert.generate("Test <test@example.com>")
        assert cert.secrets is not None
        assert len(str(cert.secrets)) > 0
        assert len(bytes(cert.secrets)) > 0

    def test_parse_roundtrip(self):
        cert = Cert.generate("Test <test@example.com>")
        parsed = Cert.from_bytes(bytes(cert))
        assert str(parsed.user_ids[0]) == "Test <test@example.com>"

    def test_split_bytes(self):
        certs = [Cert.generate(f"Test {i}") for i in range(3)]
        combined = b"".join(bytes(c) for c in certs)
        split = Cert.split_bytes(combined)
        assert len(split) == 3

    def test_generate_multiple_user_ids(self):
        cert = Cert.generate(user_ids=["First", "Second", "Third"])
        assert len(cert.user_ids) == 3

    def test_generate_rfc9580(self):
        cert = Cert.generate("Modern <modern@example.com>", profile=Profile.RFC9580)
        assert len(cert.fingerprint) > 0

    def test_expiration_with_validity(self):
        cert = Cert.generate(user_id="test", validity_seconds=3600)
        assert cert.expiration is not None

    def test_expiration_none(self):
        cert = Cert.generate(user_id="test", validity_seconds=None)
        assert cert.expiration is None

    def test_default_has_expiration(self):
        cert = Cert.generate("test")
        assert cert.expiration is not None

    def test_merge(self, wiktor_key, wiktor_fresh_key):
        merged = wiktor_key.merge(wiktor_fresh_key)
        assert merged is not None

    def test_user_id_listing(self, wiktor_key):
        assert str(wiktor_key.user_ids[0]).startswith("Wiktor Kwapisiewicz")

    def test_add_user_id(self):
        cert = Cert.generate("Alice <alice@example.com>")
        assert len(cert.user_ids) == 1
        cert = cert.add_user_id(
            value="Alice <alice@company.invalid>",
            certifier=cert.secrets.certifier(),
        )
        assert len(cert.user_ids) == 2

    def test_revoke_user_id(self):
        cert = Cert.generate("Bob <bob@example.com>")
        cert = cert.add_user_id(
            value="Bob <bob@company.invalid>",
            certifier=cert.secrets.certifier(),
        )
        assert len(cert.user_ids) == 2

        revocation = cert.revoke_user_id(
            user_id=cert.user_ids[1], certifier=cert.secrets.certifier()
        )
        cert = Cert.from_bytes(bytes(cert) + bytes(revocation))
        assert len(cert.user_ids) == 1

    def test_has_secret_keys(self):
        c = Cert.generate("Testing key <test@example.com>")
        assert c.has_secret_keys

        public_parts = Cert.from_bytes(f"{c}".encode("utf8"))
        assert not public_parts.has_secret_keys
        assert public_parts.secrets is None

        private_parts = Cert.from_bytes(f"{c.secrets}".encode("utf8"))
        assert private_parts.has_secret_keys


class TestNotations:
    def test_read_notation(self, wiktor_key):
        notation = wiktor_key.user_ids[0].notations[0]
        assert notation.key == "proof@metacode.biz"
        assert notation.value == "dns:metacode.biz?type=TXT"

    def test_add_notation(self, signing_key):
        assert len(signing_key.user_ids[0].notations) == 0
        cert = signing_key.set_notations(
            signing_key.secrets.certifier(),
            [Notation("proof@metacode.biz", "dns:metacode.biz")],
        )
        assert len(cert.user_ids[0].notations) == 1
        notation = cert.user_ids[0].notations[0]
        assert notation.key == "proof@metacode.biz"
        assert notation.value == "dns:metacode.biz"


class TestKeyExpiration:
    def test_no_expiration(self, signing_key):
        assert signing_key.expiration is None

    def test_has_expiration(self, wiktor_key):
        assert str(wiktor_key.expiration) == "2022-12-31 12:00:02+00:00"

    def test_set_expiration(self, signing_key):
        assert signing_key.expiration is None
        expiration = datetime.fromisoformat("2021-11-04T00:05:23+00:00")
        updated = signing_key.set_expiration(
            expiration=expiration, certifier=signing_key.secrets.certifier()
        )
        assert str(updated.expiration) == "2021-11-04 00:05:23+00:00"


class TestKeyRevocation:
    def test_revoke(self):
        cert = Cert.generate("Test Revocation <revoke@example.com>")
        revocation = cert.revoke(certifier=cert.secrets.certifier())
        assert not cert.is_revoked

        revoked = Cert.from_bytes(bytes(cert) + bytes(revocation))
        assert revoked.is_revoked


class TestSig:
    def test_parse_from_file(self):
        sig = Sig.from_file(fixture_path("sig.pgp"))
        assert sig.issuer_fingerprint == "e8f23996f23218640cb44cbe75cf5ac418b8e74c"
        assert sig.issuer_key_id == "75cf5ac418b8e74c"
        assert sig.created == datetime.fromisoformat("2023-07-19T18:14:01+00:00")
        assert sig.expiration is None
        assert sig.signers_user_id is None


class TestPacketPile:
    def test_iterate_packets(self):
        cert = Cert.generate("Test <test@example.com>")
        pile = PacketPile.from_bytes(bytes(cert))
        tags = [p.tag for p in pile]
        assert Tag.PublicKey in tags
        assert Tag.UserID in tags
        assert Tag.Signature in tags

    def test_packet_body(self):
        cert = Cert.generate("Test <test@example.com>")
        packet = list(PacketPile.from_bytes(bytes(cert)))[0]
        assert packet.tag == Tag.PublicKey
        assert len(packet.body) > 0


class TestArmor:
    def test_armor_public_key(self):
        cert = Cert.generate("Test <test@example.com>")
        armored = armor(bytes(cert), ArmorKind.PublicKey)
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in armored
        assert "-----END PGP PUBLIC KEY BLOCK-----" in armored

    def test_armor_message(self):
        armored = armor(b"dummy data", ArmorKind.Message)
        assert "BEGIN PGP MESSAGE" in armored

    def test_armor_signature(self):
        armored = armor(b"dummy data", ArmorKind.Signature)
        assert "BEGIN PGP SIGNATURE" in armored
