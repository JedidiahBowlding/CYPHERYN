import base64
import json

from cryptography.fernet import Fernet, InvalidToken


class ProviderSecretError(ValueError):
    pass


def encrypt_credentials(credentials: dict, key: str) -> str:
    try:
        payload = json.dumps(credentials, separators=(",", ":"), sort_keys=True).encode()
        return Fernet(key.encode()).encrypt(payload).decode()
    except (ValueError, TypeError) as exc:
        raise ProviderSecretError("Invalid provider encryption key") from exc


def decrypt_credentials(ciphertext: str, key: str) -> dict:
    try:
        value = json.loads(Fernet(key.encode()).decrypt(ciphertext.encode()))
    except (
        InvalidToken,
        ValueError,
        TypeError,
        json.JSONDecodeError,
        base64.binascii.Error,
    ) as exc:
        raise ProviderSecretError("Provider credentials could not be decrypted") from exc
    if not isinstance(value, dict):
        raise ProviderSecretError("Provider credentials must be an object")
    return value
