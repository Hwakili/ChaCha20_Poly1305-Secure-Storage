# # Secure Storage using ChaCha20-Poly1305 



## Overview 
This project, from the *Cryptography and Applications* unit at Manchester Metropolitan University, successfully fulfills its main objectives to deliver a secure storage and backup system. 

The system allows files and folders to be encrypted so that only appropriate users can read or write to them, and enables keys for those files to be shared among multiple users and systems in a controlled way. 

Its design is based on the ChaCha20-Poly1305 authenticated encryption scheme, combined with asymmetric cryptography for key distribution and digital signatures. 


# Student Details: 

Student ID: 25934110 
Student Email: 25934110@stu.mmu.ac.uk 

--- 

This system encrypts your backups. 
- It will encrypt individual files or entire folders. 
- Two independent users of a system that employs independent cryptographic keys. 
- Authenticated encryption (confidentiality + integrity) 
- Asymmetric cryptography, for example, makes possible the secure sharing of secret keys. 
- Digital signatures verify that an item is authentic and hasn’t been altered. 
- Explicit tamper test demonstrating integrity enforcement 

--- 

## Algorithms and Primitives Used 
1. ChaCha20-Poly1305 is a method for encrypting data. 
2. Elliptic-curve key agreement uses X25519 algorithm to wrap the DEK but this only provides for key exchange, not encryption. 
3. The session keys themselves are derived from the symmetric shared key using HKDF and SHA-256. 
4. Ed25519 for digital signatures: Their system uses an Edwards-curve, rather than other elliptic curves. 
5. **SHA-256** – integrity verification (hash comparison) 

--- 

## How to Run (Google Colab) 
1. Open the `code_walkthrough.md file or run each code in order according to the file structure
2. Copy each cell and run in google colab environment. 
3. Observe: 
- Successful encryption/decryption for UserA and UserB 
- SHA-256 hashes of the data before and after decryption, verifying data integrity. 
- Tamper test failure detection 

All test data is automatically generated, so it is not necessary to upload any files. 

--- 

## File Structure 
1. `key_management.py`: Generates, wraps, and unwraps keys. 
2. `backup_crypto.py` – encryption, signing, container handling
3. `File_cryptography.py` - Text file encryption and verification 
4. `Folder_cryptography.py` - Zip folder encryption and verification
5. `DESIGN_RATIONALE.md` – cryptographic design decisions 
6. `CODE_WALKTHROUGH.md.` - detailed explanation of the code


## AI Assistance Disclosure
Generative AI tools were used in a limited advisory role to clarify cryptographic concepts and review structure.  
All code, comments, explanations, and design decisions were written, modified, and validated by the author, who fully understands the implementation.  
No AI-generated code was used without significant modification and comprehension.

---
