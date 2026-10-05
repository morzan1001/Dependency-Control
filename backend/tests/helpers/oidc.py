from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

_PUBLIC_JWK = RSAAlgorithm.to_jwk(
    rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(), as_dict=True
)


def rsa_public_jwk(kid: str) -> dict:
    return {**_PUBLIC_JWK, "kid": kid}
