import pysequoia
import subprocess


# the types can go in quotes, only MyPy or humans really care
def sign(data: bytes, signer: "pysequoia.PySigner") -> bytes:
    return pysequoia.sign(signer, data)


# this is my key-id, will want to use one's own
data = subprocess.check_output(
    ["sq", "key", "export", "--cert", "9D5A2BD5688ECB889DEBCD3FC2602803128069A7"]
)
cert = pysequoia.Cert.from_bytes(data)
result = sign(b"attack at dawn", cert.secrets.signer("passphrase"))
print(result)
