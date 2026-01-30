# Design Rationale

## Problem Statement
The task requires implementing a secure storage system capable of encrypting files and folders while supporting multiple users with separate keys. The system must ensure confidentiality, integrity, and secure key sharing.

---

## Choice of ChaCha20-Poly1305
ChaCha20-Poly1305 was selected due to:
- Strong security guarantees as an AEAD construction
- Resistance to common implementation errors
- High performance in software without hardware acceleration
- Widespread adoption in TLS 1.3 and modern protocols

Using AEAD ensures encryption and authentication are inseparable, preventing misuse.

---

## Key Management Strategy
A hybrid encryption model (KEM/DEM) is used:
- A random symmetric **Data Encryption Key (DEK)** encrypts the data
- The DEK is wrapped separately for each user using **X25519**
- **HKDF** derives a secure wrapping key from the shared secret

This allows multiple users to decrypt the same data independently without sharing symmetric keys.

---

## Use of Digital Signatures
Ed25519 signatures are applied to each encrypted container:
- Ensures data authenticity
- Detects tampering before decryption
- Prevents chosen-ciphertext and rollback attacks

Verification occurs before decryption as a security best practice.

---

## Folder Encryption Approach
Folders are serialized into ZIP archives before encryption:
- Preserves directory structure
- Allows encryption using standard byte-based cryptographic primitives
- Demonstrates extensibility beyond the minimum requirement

---

## Security Properties Achieved
- Confidentiality: ChaCha20 encryption
- Integrity: Poly1305 MAC + SHA-256 verification
- Authenticity: Ed25519 signatures
- Key separation: Per-file and per-folder DEKs
- Tamper detection: Explicit adversarial test

---

## Conclusion
The design meets all minimum requirements and includes multiple extensions aligned with industry best practices and academic standards.
