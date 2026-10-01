import os
import subprocess
import sys

import pytest

import test_pysequoia as cases


@pytest.mark.skipif(
    os.environ.get("PYSEQUOIA_TEST_SYSTEM_POLICY_DEFAULT") != "1",
    reason="requires a build with system-policy-default",
)
def test_system_policy_default(tmp_path):
    config = tmp_path / "sequoia.config"
    config.write_text('[hash_algorithms]\nsha1 = "always"\n')
    restricted_config = tmp_path / "restricted.config"
    restricted_config.write_text('[hash_algorithms]\nsha1 = "never"\n')
    signed = tmp_path / "signed.pgp"
    signed.write_bytes(cases.TestVerify._sha1_signed_data())

    script = """
import sys
from pysequoia import Cert, Policy, verify

cert = Cert.from_file(sys.argv[2])
signed = open(sys.argv[1], "rb").read()
assert verify(signed, lambda _: [cert]).bytes == b"data to be signed"
assert verify(signed, lambda _: [cert], policy=Policy.default()).bytes == b"data to be signed"
try:
    verify(signed, lambda _: [cert], policy=Policy.from_sequoia_config_file(sys.argv[3]))
except Exception:
    pass
else:
    raise AssertionError("explicit restrictive policy should reject SHA-1")
"""
    env = os.environ.copy()
    env["SEQUOIA_CRYPTO_POLICY"] = str(config)
    subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(signed),
            cases.fixture_path("signing-key.asc"),
            str(restricted_config),
        ],
        env=env,
        check=True,
    )

    config.write_text('[hash_algorithms]\nsha256 = "never"\n')
    cert_script = """
import sys
from pysequoia import Cert

cert = Cert.from_file(sys.argv[1])
try:
    cert.user_ids
except Exception:
    pass
else:
    raise AssertionError("the default certificate policy should reject SHA-256")
"""
    subprocess.run(
        [sys.executable, "-c", cert_script, cases.fixture_path("signing-key.asc")],
        env=env,
        check=True,
    )

    config.write_text("not valid TOML = [")
    result = subprocess.run(
        [sys.executable, "-c", "import pysequoia"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Failed to parse" in result.stderr or "parse" in result.stderr.lower()

    config.unlink()
    result = subprocess.run(
        [sys.executable, "-c", "import pysequoia"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "no such file" in result.stderr.lower()
