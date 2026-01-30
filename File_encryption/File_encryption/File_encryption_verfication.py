import os
from pathlib import Path
import key_management as km
import backup_crypto as bc

# --- USER INITIALISATION ---
# Requirement: two different users with separate keys
# Using km module to generate X25519 (encryption) and Ed25519 (signing) pairs
userA = km.generate_user("UserA")
userB = km.generate_user("UserB")

print(blue("Users initialised"))
show_public_keys(userA)
show_public_keys(userB)

# --- DATA PREPARATION ---
# Requirement: encrypted backup of a FILE (minimum)
# Creating a dummy file to simulate the backup process for Task 2
msg = "This is an Implementation of ChaCha20-Poly1305 for the purpose of Task 2"
work_dir = Path("/content/sample_data_folder")
work_dir.mkdir(parents=True, exist_ok=True)
(work_dir / "notes.txt").write_text(msg)

# Reading as bytes for crypto operations; capturing pre-encryption hash for integrity check
plain_file = (work_dir / "notes.txt").read_bytes()
print(blue("\nOriginal file text:"))
print(plain_file.decode())
file_hash_before = sha256_hex(plain_file)
print("SHA-256 (before):", file_hash_before)

# --- ENCRYPTION PHASE ---
# Requirement: data encryption + integrity (AEAD)
# Security Best Practice: Use a unique Data Encryption Key (DEK) for every session/backup
dek = os.urandom(32)  # Generate random 256-bit key
nonce = os.urandom(bc.NONCE_SIZE)
# AAD (Additional Authenticated Data) ensures the context (filename) is bound to the ciphertext
aad = b"demo:file:notes.txt"

# Utilizing ChaCha20-Poly1305 for high-speed authenticated encryption
cipher = bc.encrypt_bytes(plain_file, dek, nonce, aad)

# --- KEY WRAPPING / SHARING ---
# Requirement: secure key sharing architecture (wrap DEK for two users)
# Following a "KEM/DEM" hybrid approach: Encrypt the file with a symmetric DEK,
# then wrap (encrypt) that DEK with each recipient's public key.
recipients = {
    userA.label: km.wrap_dek_for_recipient(dek, userA.x25519_pk),
    userB.label: km.wrap_dek_for_recipient(dek, userB.x25519_pk),
}

# --- SIGNATURE ---
# Extension: digital signature over container to ensure Non-Repudiation
# Building a header containing the nonce, AAD, and the wrapped keys
header_data = bc.build_header(nonce=nonce, aad=aad, recipients=recipients, signer=userA.label)

# Signing the entire package (header + ciphertext) using User A's private key
signature_value = bc.sign_container(header_data, cipher, userA.ed25519_sk)
header_data["signature"] = signature_value

# Serialise to disk as a .c20p (ChaCha20-Poly) custom format
container_bytes = bc.pack_container(header_data, cipher)
enc_path = Path("/content/notes_txt_backup.c20p")
enc_path.write_bytes(container_bytes)
print(blue("\nEncrypted file container written:"), str(enc_path))

# --- DECRYPTION & VERIFICATION PHASE ---
# Logic: Verify that both UserA and UserB can independently recover the data
loaded_container = bc.unpack_container(enc_path.read_bytes())

# Step 1: Verify authenticity before attempting decryption (prevents padding oracles/CCA)
bc.verify_container_signature(loaded_container.header, loaded_container.ciphertext, userA.ed25519_pk)

# Step 2: Decrypt as UserA
# Retrieve UserA's version of the wrapped DEK and unwrap it with their private key
wrapped_dek_A = loaded_container.header["recipients"][userA.label]
dekA = km.unwrap_dek_for_recipient(wrapped_dek_A, userA.x25519_sk)

nonce_decoded = bc.b64_decode(loaded_container.header["nonce"])
aad_decoded = bc.b64_decode(loaded_container.header["aad"])

plainA = bc.decrypt_bytes(
    loaded_container.ciphertext,
    dekA,
    nonce_decoded,
    aad_decoded
)

print(blue("\nDecrypted (UserA):"))
print(plainA.decode())
file_hash_after_A = sha256_hex(plainA)
print("SHA-256 (UserA):", file_hash_after_A)

# Step 3: Decrypt as UserB (Validating multi-recipient access)
wrapped_dek_B = loaded_container.header["recipients"][userB.label]
dekB = km.unwrap_dek_for_recipient(wrapped_dek_B, userB.x25519_sk)

plainB = bc.decrypt_bytes(
    loaded_container.ciphertext,
    dekB,
    nonce_decoded,
    aad_decoded
)

print(blue("\nDecrypted (UserB):"))
print(plainB.decode())
file_hash_after_B = sha256_hex(plainB)
print("SHA-256 (UserB):", file_hash_after_B)

# --- FINAL INTEGRITY CHECK ---
# Ensure that the round-trip didn't corrupt the data and both users got the same result
if file_hash_before == file_hash_after_A == file_hash_after_B:
    print(green("\nPASS file round trip - preserved content (hashes match)"))
else:
    print(red("\nFAIL file hashes do not match"))
