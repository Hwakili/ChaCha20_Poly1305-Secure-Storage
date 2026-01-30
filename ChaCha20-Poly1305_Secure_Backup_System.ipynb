## Secure Backup System Using ChaCha20-Poly1305

##Implementation Task – Secure Storage of Data

#Overview

This project implements a secure backup system that encrypts files and folders while supporting multiple users with separate cryptographic keys. The design focuses on confidentiality, integrity, authenticity, and sound key management practices, aligned with modern cryptographic standards.

The system uses ChaCha20-Poly1305 for authenticated encryption and integrates asymmetric cryptography for secure key distribution and digital signatures.

##Environment Setup (Google Colab)

!pip install cryptography

##Imports and Global Setup

import os
import json
import zipfile
import hashlib
import shutil
import base64
import struct
from dataclasses import dataclass
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidTag

##Key Management 

@dataclass
class UserIdentity:
    username: str
    enc_private: X25519PrivateKey
    enc_public: X25519PublicKey
    sig_private: Ed25519PrivateKey
    sig_public: Ed25519PublicKey

def generate_user(username: str) -> UserIdentity:
    enc_private = X25519PrivateKey.generate()
    sig_private = Ed25519PrivateKey.generate()
    return UserIdentity(
        username=username,
        enc_private=enc_private,
        enc_public=enc_private.public_key(),
        sig_private=sig_private,
        sig_public=sig_private.public_key()
    )
