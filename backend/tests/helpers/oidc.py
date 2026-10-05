import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_JWK = RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key(), as_dict=True)


def rsa_public_jwk(kid: str) -> dict:
    return {**_PUBLIC_JWK, "kid": kid}


def ci_token(claims: dict) -> str:
    return jwt.encode(claims, _PRIVATE_KEY, algorithm="RS256", headers={"kid": "ci-key"})
