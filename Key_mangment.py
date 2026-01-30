%%writefile key_management.py
import os
import base64
from dataclasses import dataclass
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# Note: Keeping metadata JSON-friendly by using base64 for bytes
# Probably should refactor this into a separate serializer class later, but good enough for now
# TODO: maybe create utils/serialization.py if this gets bigger?

"""Helper functions to convert between raw bytes and base64 strings
so that cryptographic values can be embedded in JSON metadata without corruption"""

def b64_encode(raw_bytes: bytes) -> str:
    # simple wrapper around base64 encoding
    return base64.b64encode(raw_bytes).decode("ascii")

def b64_decode(text: str) -> bytes:
    # decode base64 string back to bytes
    return base64.b64decode(text.encode("ascii"))


@dataclass
class UserIdentity:
    """
    Each user has:
      - X25519 for key agreement (wrapping/unwrapping the DEK for that user)
      - Ed25519 for signatures (used to sign backup containers in backup_crypto.py)

    Keeping both key types separate is standard practice - don't reuse keys for different purposes!
    """
    label: str
    x25519_sk: X25519PrivateKey
    x25519_pk: X25519PublicKey
    ed25519_sk: Ed25519PrivateKey
    ed25519_pk: Ed25519PublicKey


def generate_user(label: str) -> UserIdentity:
    # Generate fresh keys for a new user
    # X25519 is for encryption/key agreement, Ed25519 is for signing
    x_private = X25519PrivateKey.generate()
    e_private = Ed25519PrivateKey.generate()

    user = UserIdentity(
        label=label,
        x25519_sk=x_private,
        x25519_pk=x_private.public_key(),
        ed25519_sk=e_private,
        ed25519_pk=e_private.public_key(),
    )
    return user


def _derive_wrap_key(shared_secret: bytes, salt: bytes) -> bytes:
    """
    Turn the X25519 shared secret into a symmetric key suitable for AEAD key wrapping.

    Using HKDF(SHA-256) here mainly because:
      1) you shouldn't use the raw DH output directly as an AEAD key (best practice)
      2) the 'info' parameter binds the derived key to this specific use case

    I remember reading somewhere that this pattern prevents key reuse issues...
    """
    # 32 bytes = 256-bit key for ChaCha20-Poly1305
    key_derivation = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"task2/dek-wrapping/v1",  # custom info string for domain separation
    )
    derived_key = key_derivation.derive(shared_secret)
    return derived_key


def wrap_dek_for_recipient(dek: bytes, recipient_x25519_pk: X25519PublicKey) -> Dict[str, Any]:
    """
    Wrap a 32-byte DEK so that *only* the intended recipient can recover it.

    How this works:
      - Generate ephemeral X25519 key for each wrap (keeps wraps unlinkable across backups)
      - Use HKDF to derive a wrapping key from the shared secret
      - Encrypt DEK with ChaCha20-Poly1305 (provides both confidentiality and integrity)

    If someone tampers with the wrapped data, decryption will fail - that's the point of AEAD!
    """
    # Sanity check the DEK
    if not isinstance(dek, (bytes, bytearray)) or len(dek) != 32:
        raise ValueError("wrap_dek_for_recipient: expected a 32-byte DEK (bytes).")

    # Generate ephemeral key pair for this specific wrap operation
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    # Perform X25519 key agreement to get shared secret
    shared_secret = ephemeral_private.exchange(recipient_x25519_pk)

    # Random salt for HKDF - makes outputs unique
    random_salt = os.urandom(16)
    wrapping_key = _derive_wrap_key(shared_secret, random_salt)

    # ChaCha20-Poly1305 needs a 96-bit (12-byte) nonce
    random_nonce = os.urandom(12)

    # Encrypt the DEK with AEAD
    cipher = ChaCha20Poly1305(wrapping_key)
    encrypted_dek = cipher.encrypt(
        random_nonce,
        dek,
        b"DEK_WRAP"  # Additional authenticated data - small label to prevent accidental reuse
    )
    # Note: encrypted_dek contains both ciphertext and the Poly1305 authentication tag

    # Package everything up for JSON storage
    wrap_info = {
        "eph_pub": b64_encode(ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
        "salt": b64_encode(random_salt),
        "nonce": b64_encode(random_nonce),
        "wrapped": b64_encode(encrypted_dek),
    }

    return wrap_info


def unwrap_dek_for_recipient(wrap_record: Dict[str, Any], recipient_x25519_sk: X25519PrivateKey) -> bytes:
    """
    Reverse of wrap_dek_for_recipient - decrypt the wrapped DEK.

    Expected failure cases:
      - wrong recipient private key -> shared secret doesn't match -> AEAD decryption fails
      - any modification to wrap_record fields -> AEAD tag verification fails

    Both cases will raise an exception, which is what we want for security.
    """
    # Parse the wrap record - need to handle potential format errors
    try:
        ephemeral_pub_key = X25519PublicKey.from_public_bytes(b64_decode(wrap_record["eph_pub"]))
        salt_bytes = b64_decode(wrap_record["salt"])
        nonce_bytes = b64_decode(wrap_record["nonce"])
        wrapped_bytes = b64_decode(wrap_record["wrapped"])
    except Exception as err:
        raise ValueError(f"unwrap_dek_for_recipient: wrap_record malformed ({type(err).__name__}).")

    # Recompute the shared secret using recipient's private key
    shared_secret = recipient_x25519_sk.exchange(ephemeral_pub_key)

    # Derive the same wrapping key
    wrapping_key = _derive_wrap_key(shared_secret, salt_bytes)

    # Decrypt and verify the DEK
    cipher = ChaCha20Poly1305(wrapping_key)
    recovered_dek = cipher.decrypt(
        nonce_bytes,
        wrapped_bytes,  # this includes ciphertext || authentication tag
        b"DEK_WRAP"     # same AAD we used during encryption
    )
    # decrypt() internally verifies the Poly1305 tag and raises exception if tampered

    # Double-check the recovered DEK is the right size
    if len(recovered_dek) != 32:
        raise ValueError("unwrap_dek_for_recipient: recovered DEK length was unexpected.")

    return recovered_dek
