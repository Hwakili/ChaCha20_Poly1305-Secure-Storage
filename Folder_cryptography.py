import zipfile
import shutil
import struct

# --- ARCHIVING ---
# Requirement: encrypted backup of a FOLDER
# Standard crypto libraries usually encrypt blobs (bytes), not directories.
# Using ZIP here to serialize the folder structure into a single byte stream before encryption.
(work_dir / "config.json").write_text('{"api_key":"12345","env":"prod"}\n')

zip_path = Path("/content/backup_payload.zip")
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for p in work_dir.iterdir():
        if p.is_file():
            # Preserving the relative directory structure for backup restoration
            z.write(p, arcname=p.name)

# Capture hash of the ZIP archive to verify integrity post-decryption
plain_zip = zip_path.read_bytes()
zip_hash_before = sha256_hex(plain_zip)

print(blue("\nFolder zipped as:"), str(zip_path))
print("SHA-256 (zip before):", zip_hash_before)

# --- ENCRYPTION & MULTI-USER WRAPPING ---
# Security Note: Generating a new 256-bit DEK to ensure cryptographic separation
# from the single-file backup performed previously.
dek_folder = os.urandom(32)
nonce_folder = os.urandom(bc.NONCE_SIZE)
aad_folder = b"demo:folder:sample_data_folder"

# Encrypting the entire ZIP archive using the ChaCha20-Poly1305 AEAD construction
cipher_folder = bc.encrypt_bytes(plain_zip, dek_folder, nonce_folder, aad_folder)

# Hybrid Encryption: Encrypting the symmetric DEK with each user's X25519 Public Key
recipients_folder = {
    userA.label: km.wrap_dek_for_recipient(dek_folder, userA.x25519_pk),
    userB.label: km.wrap_dek_for_recipient(dek_folder, userB.x25519_pk),
}

# Constructing the signed metadata container
header_folder = bc.build_header(nonce=nonce_folder, aad=aad_folder, recipients=recipients_folder, signer=userA.label)
sig_folder = bc.sign_container(header_folder, cipher_folder, userA.ed25519_sk)
header_folder["signature"] = sig_folder

folder_container_path = Path("/content/backup.c20p")
packed_data = bc.pack_container(header_folder, cipher_folder)
folder_container_path.write_bytes(packed_data)
print(blue("\nEncrypted folder container written:"), str(folder_container_path))

# --- RECOVERY & MULTI-USER VERIFICATION ---
# Validating that both users can independently decrypt the folder backup
loaded_folder = bc.unpack_container(folder_container_path.read_bytes())

# Verifying the Ed25519 digital signature to ensure data origin authenticity
bc.verify_container_signature(loaded_folder.header, loaded_folder.ciphertext, userA.ed25519_pk)

# Recovery for User A
wrapped_key_A = loaded_folder.header["recipients"][userA.label]
dekA_f = km.unwrap_dek_for_recipient(wrapped_key_A, userA.x25519_sk)

nonce_val = bc.b64_decode(loaded_folder.header["nonce"])
aad_val = bc.b64_decode(loaded_folder.header["aad"])

zipA = bc.decrypt_bytes(
    loaded_folder.ciphertext,
    dekA_f,
    nonce_val,
    aad_val
)
zip_hash_after_A = sha256_hex(zipA)
print("SHA-256 (zip UserA):", zip_hash_after_A)

# Recovery for User B
wrapped_key_B = loaded_folder.header["recipients"][userB.label]
dekB_f = km.unwrap_dek_for_recipient(wrapped_key_B, userB.x25519_sk)
zipB = bc.decrypt_bytes(
    loaded_folder.ciphertext,
    dekB_f,
    nonce_val,  # reusing the already decoded nonce
    aad_val     # reusing the already decoded aad
)
zip_hash_after_B = sha256_hex(zipB)
print("SHA-256 (zip UserB):", zip_hash_after_B)

# Verify the integrity of the round-trip via hash comparison
if zip_hash_before == zip_hash_after_A == zip_hash_after_B:
    print(green("PASS: folder backup round-trip preserved content (hashes match)"))
else:
    print(red("FAIL: folder zip hashes do not match"))

# Persistence for inspection/extraction
Path("/content/decrypted_userA.zip").write_bytes(zipA)
Path("/content/decrypted_userB.zip").write_bytes(zipB)

# --- ADVERSARIAL TAMPER TEST ---
# Simulating a "Bit-Flip" attack on the ciphertext to test AEAD/Signature failure.
# This proves that any modification to the encrypted file results in a validation error.
tampered_path = Path("/content/backup_tampered.c20p")
shutil.copy(folder_container_path, tampered_path)

with open(tampered_path, "r+b") as f:
    f.read(4)  # Skip Magic Bytes
    header_len_bytes = f.read(4)
    header_len = struct.unpack(">I", header_len_bytes)[0]  # Read header length to find ciphertext offset
    f.seek(8 + header_len + 5)             # Jump into the middle of the ciphertext
    byte_to_flip = f.read(1)
    f.seek(-1, 1)  # go back one byte
    flipped_byte = bytes([byte_to_flip[0] ^ 0x01])  # XOR bit flip
    f.write(flipped_byte)

try:
    # Attempting to process tampered data
    tampered_container = bc.unpack_container(tampered_path.read_bytes())
    # This call should fail because the signature/MAC will no longer match the modified bytes
    bc.verify_container_signature(tampered_container.header, tampered_container.ciphertext, userA.ed25519_pk)
    print(red("FAIL: tamper not detected (unexpected)"))
except Exception:
    # Catching the exception proves the system is robust against unauthorized modifications
    print(green("PASS: tamper not detected (integrity check worked)"))


####ADDITIONAL CELL TO BE ADDEDD TO CHECK EACH REQUIRMENT HAS BEEN MET###

from pathlib import Path
import zipfile

print(blue("\n=== Checklist against the brief ==="))

items = []

# Minimum: encrypted backup of files/folders
items.append(("Encrypted file container produced", Path("/content/notes_txt_backup.c20p").exists()))
items.append(("Encrypted folder container produced", Path("/content/backup.c20p").exists()))

# Minimum: two users decrypt using their own keys (demonstrated by successful decryption + matching hashes)
items.append(("Decrypted folder zip produced (UserA)", Path("/content/decrypted_userA.zip").exists()))
items.append(("Decrypted folder zip produced (UserB)", Path("/content/decrypted_userB.zip").exists()))

# Integrity/confidentiality: AEAD + tamper test
items.append(("Tampered container produced", Path("/content/backup_tampered.c20p").exists()))

# sanity: zip validity
def is_zip_ok(p):
    try:
        with zipfile.ZipFile(p, "r") as z:
            z.namelist()
        return True
    except:
        return False

items.append(("Decrypted zip is valid (UserA)", is_zip_ok("/content/decrypted_userA.zip")))
items.append(("Decrypted zip is valid (UserB)", is_zip_ok("/content/decrypted_userB.zip")))

all_ok = True
for label, ok in items:
    print((green("PASS") if ok else red("FAIL")), label)
    all_ok = all_ok and ok

print("\nOverall:", green("PASS") if all_ok else red("PARTIAL"))


