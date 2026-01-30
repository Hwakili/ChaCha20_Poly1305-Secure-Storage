# Secure Storage using ChaCha20-Poly1305



## Overview
This project implements a secure storage and backup system as part of the *Cryptography and Applications* module for Manchester Metropolitan University 
The system encrypts files and folders while enforcing confidentiality, integrity, and controlled key sharing between multiple users.

The design uses the ChaCha20-Poly1305 authenticated encryption scheme, combined with asymmetric cryptography for secure key distribution and digital signatures.


# Student Details: 

Name: Hamza Wakili 
Student ID: 25934110 
Email: Hamza_I_Wakili@stu.mmu.ac.uk 

---

## Features
- Encrypted backup of individual files and entire folders
- Separate cryptographic keys for two independent users
- Authenticated encryption (confidentiality + integrity)
- Secure key sharing using asymmetric cryptography
- Digital signatures for authenticity and tamper detection
- Explicit tamper test demonstrating integrity enforcement

---

## Algorithms and Primitives Used
- **ChaCha20-Poly1305** (AEAD) – data encryption and integrity
- **X25519** – Secure elliptic-curve for key agreement for DEK wrapping
- **HKDF (SHA-256)** – key derivation from symmetric shared keys 
- **Ed25519** – Edwards curve for digital signatures
- **SHA-256** – integrity verification (hash comparison)

---

## How to Run (Google Colab)
1. Open the notebook `task2_secure_backup.ipynb`
2. Run all cells in order from top to bottom
3. Observe:
   - Successful encryption/decryption for UserA and UserB
   - Matching SHA-256 hashes before and after decryption
   - Tamper test failure detection

No file uploads are required; all test data is generated automatically.

---

## File Structure
- `key_management.py` – key generation, wrapping, and unwrapping
- `backup_crypto.py` – encryption, signing, container handling
- `task2_secure_backup.ipynb` – executable demonstration
- `DESIGN_RATIONALE.md` – cryptographic design decisions
- `CODE_WALKTHROUGH.md` – detailed explanation of the code
- `REFERENCES.md` – academic references

---

## AI Assistance Disclosure
Generative AI tools were used in a limited advisory role to clarify cryptographic concepts and review structure.  
All code, comments, explanations, and design decisions were written, modified, and validated by the author, who fully understands the implementation.  
No AI-generated code was used without significant modification and comprehension.

---
