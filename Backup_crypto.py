%%writefile backup_crypto.py
import json
import struct
import base64
from dataclasses import dataclass
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Protocol Constants
MAGIC = b"C20P"          # Custom file signature to identify our container format
NONCE_SIZE = 12          # 96-bit nonce for RFC 8439 compliance (standard for ChaCha20)


def b64_encode(raw: bytes) -> str:
    """Helper to convert raw bytes to URL/JSON safe strings"""
    return base64.b64encode(raw).decode("ascii")

def b64_decode(txt: str) -> bytes:
    """Helper to revert base64 strings back to original bytes"""
    return base64.b64decode(txt.encode("ascii"))


@dataclass
class Container:
    """
    Object representation of our unpacked backup file.
    Makes it easier to access attributes instead of dealing with raw tuples.
    """
    header: Dict[str, Any]
    ciphertext: bytes


def _canonical_header_bytes(header: Dict[str, Any]) -> bytes:
    """
    Critical for Signature Stability!

    JSON dicts are unordered by default in Python < 3.7 (though they're ordered now).
    We still need to sort keys and remove whitespace to ensure the same input
    always produces the exact same byte-string.

    Otherwise digital signature verification will fail randomly depending on
    how Python decides to serialize the dict... learned this the hard way.
    """
    header_copy = dict(header)
    header_copy["signature"] = None  # Don't sign the signature field itself (that would be circular!)

    # sort_keys=True and no whitespace for deterministic output
    canonical_json = json.dumps(header_copy, sort_keys=True, separators=(",", ":"))
    return canonical_json.encode("utf-8")


def pack_container(header: Dict[str, Any], ciphertext: bytes) -> bytes:
    """
    Serializes data into a custom binary format:

    Format:
    [4 bytes MAGIC] [4 bytes Header Length (Big Endian)] [JSON Header] [Ciphertext]

    Using our own format instead of something like protobuf to keep dependencies minimal.
    """
    # Serialize header to JSON bytes
    header_blob = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Pack header length as 32-bit unsigned int in Network Byte Order (Big Endian)
    # '>I' means: > = big endian, I = unsigned int (4 bytes)
    header_length_bytes = struct.pack(">I", len(header_blob))

    # Concatenate everything together
    container_bytes = MAGIC + header_length_bytes + header_blob + ciphertext
    return container_bytes


def unpack_container(blob: bytes) -> Container:
    """
    Parses a C20P file, validating the structure before loading into memory.

    Will raise ValueError if the file is corrupted or not a valid C20P container.
    """
    # Basic validation - file must at least have magic + length field
    if len(blob) < 8 or blob[:4] != MAGIC:
        raise ValueError("unpack_container: not a valid C20P container (bad magic/short file).")

    # Extract the length of the header so we know where ciphertext starts
    header_len = struct.unpack(">I", blob[4:8])[0]

    # Sanity check the header length
    if header_len <= 0 or 8 + header_len > len(blob):
        raise ValueError("unpack_container: header length is inconsistent with file size.")

    # Parse the JSON header
    header_bytes = blob[8:8 + header_len]
    header = json.loads(header_bytes.decode("utf-8"))

    # Everything after the header is ciphertext
    ciphertext = blob[8 + header_len:]

    return Container(header=header, ciphertext=ciphertext)


def build_header(*, nonce: bytes, aad: bytes, recipients: Dict[str, Any], signer: str) -> Dict[str, Any]:
    """
    Metadata constructor - builds the header dict that goes into the container.

    Version 1 implementation focusing on what's needed for decryption and audit trails.
    If we need to add fields later, we can bump the version number.
    """
    header_dict = {
        "version": 1,
        "alg": "ChaCha20-Poly1305",  # AEAD algorithm identifier
        "nonce": b64_encode(nonce),
        "aad": b64_encode(aad),
        "recipients": recipients,     # Dict of wrapped DEKs per recipient
        "signer": signer,             # Who signed this container
        "signature": None,            # Will be filled in by sign_container()
    }
    return header_dict


def encrypt_bytes(plaintext: bytes, dek: bytes, nonce: bytes, aad: bytes) -> bytes:
    """
    Implements Authenticated Encryption with Associated Data (AEAD).

    This doesn't just hide the data - it also creates an authentication tag (Poly1305)
    that prevents any modification of either the ciphertext OR the AAD (like filenames).

    Any tampering -> decryption fails with InvalidTag exception.
    """
    # Validate inputs
    if len(dek) != 32:
        raise ValueError("encrypt_bytes: DEK must be 32 bytes for ChaCha20-Poly1305.")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"encrypt_bytes: nonce must be {NONCE_SIZE} bytes.")

    cipher = ChaCha20Poly1305(dek)
    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    return ciphertext


def decrypt_bytes(ciphertext: bytes, dek: bytes, nonce: bytes, aad: bytes) -> bytes:
    """
    Decrypts and validates the authentication tag automatically.

    Security note: The .decrypt() method verifies the Poly1305 tag internally.
    If even a single bit was changed in the ciphertext or AAD, it throws InvalidTag.
    """
    cipher = ChaCha20Poly1305(dek)
    plaintext = cipher.decrypt(nonce, ciphertext, aad)
    return plaintext


def sign_container(header: Dict[str, Any], ciphertext: bytes, sk: Ed25519PrivateKey) -> str:
    """
    Digitally signs the package using Ed25519 (asymmetric signatures).

    We sign a concatenation of the canonical header and the ciphertext
    to bind them together cryptographically. This prevents mix-and-match attacks
    where someone might try to swap headers between different containers.
    """
    # Create message to sign = canonical header bytes + ciphertext
    message_to_sign = _canonical_header_bytes(header) + ciphertext

    # Generate Ed25519 signature
    signature = sk.sign(message_to_sign)

    # Return as base64 string for JSON storage
    return b64_encode(signature)


def verify_container_signature(header: Dict[str, Any], ciphertext: bytes, pk: Ed25519PublicKey) -> None:
    """
    Verifies that the file hasn't been altered since it was signed by the original sender.

    This provides 'Integrity' and 'Authenticity' on top of the 'Confidentiality'
    we get from encryption.

    Raises exception if verification fails - caller should handle that.
    """
    # Make sure there's actually a signature to verify
    if not header.get("signature"):
        raise ValueError("verify_container_signature: signature missing from header.")

    # Decode the signature from base64
    signature_bytes = b64_decode(header["signature"])

    # Reconstruct the exact message that was signed
    message = _canonical_header_bytes(header) + ciphertext

    # Ed25519 verify - throws exception if signature is invalid
    pk.verify(signature_bytes, message)
    # If we get here without exception, signature is valid!
