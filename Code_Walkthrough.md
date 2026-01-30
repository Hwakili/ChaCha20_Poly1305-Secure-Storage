# Code Walkthrough

This document explains the implementation line by line and function by function to demonstrate full understanding of the system.

---

## key_management.py

### generate_user(label)
Creates a new user identity with:
- X25519 key pair for key agreement
- Ed25519 key pair for digital signatures

Key separation prevents reuse across cryptographic purposes.

---

### wrap_dek_for_recipient(dek, recipient_public_key)
Wraps a symmetric DEK so only the intended user can recover it.

Steps:
1. Generate an ephemeral X25519 key pair
2. Perform Diffie-Hellman key agreement
3. Derive a wrapping key using HKDF
4. Encrypt the DEK using ChaCha20-Poly1305

Any tampering causes decryption to fail.

---

### unwrap_dek_for_recipient(wrap_record, recipient_private_key)
Reverses the wrapping process:
- Recomputes the shared secret
- Derives the same wrapping key
- Decrypts and authenticates the DEK

Failure indicates incorrect keys or tampering.

---

## backup_crypto.py

### encrypt_bytes(plaintext, key, nonce, aad)
Encrypts data using ChaCha20-Poly1305.
The output includes both ciphertext and authentication tag.

---

### decrypt_bytes(ciphertext, key, nonce, aad)
Decrypts and verifies ciphertext.
Raises an exception if authentication fails.

---

### sign_container(header, ciphertext, signing_key)
Generates an Ed25519 signature over metadata and ciphertext.

---

### verify_container_signature(header, ciphertext, public_key)
Verifies the signature before decryption.
Ensures authenticity and integrity.

---

### pack_container / unpack_container
Serializes and parses encrypted containers into a portable binary format.

---

## Notebook Execution

The notebook demonstrates:
- File encryption and decryption
- Folder encryption via ZIP archives
- Hash comparisons using SHA-256
- Multi-user access using separate keys
- Tamper detection via bit-flipping attack

Matching hashes confirm correctness; tamper detection confirms integrity enforcement.

---

## Summary
Each function directly maps to a security requirement in the brief, and the workflow demonstrates correct cryptographic usage throughout.
