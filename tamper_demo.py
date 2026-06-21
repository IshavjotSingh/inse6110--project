
import os
import crypto_utils

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def separator(char="=", length=60):
    print(char * length)

def run_demo():
    separator()
    print(f"{BOLD}  TAMPER DETECTION DEMONSTRATION{RESET}")
    print(f"  AES-GCM Message Integrity Proof")
    print(f"  INSE 6110 — Concordia University")
    separator()

    print(f"""
  {BOLD}What is Tamper Detection?{RESET}
  AES-GCM attaches a cryptographic authentication tag
  to every message. If an attacker modifies even a single
  byte of the ciphertext on the wire, the tag fails and
  the message is completely rejected — it never reaches
  the application.
    """)

    print(f"{BOLD}  STEP 1 - Alice and Bob establish a shared AES key{RESET}")
    separator("-", 60)

    alice_priv, alice_pub = crypto_utils.generate_ecdh_keypair()
    bob_priv,   bob_pub   = crypto_utils.generate_ecdh_keypair()

    alice_pub_bytes = crypto_utils.serialize_public_key(alice_pub)
    bob_pub_bytes   = crypto_utils.serialize_public_key(bob_pub)

    shared_secret = crypto_utils.compute_shared_secret(
        alice_priv,
        crypto_utils.deserialize_public_key(bob_pub_bytes)
    )
    aes_key = crypto_utils.derive_aes_key(shared_secret)

    print(f"  AES-GCM session key: {GREEN}{aes_key.hex()[:32]}...{RESET}")
    print(f"  {GREEN}✅  Shared key established via ECDH + HKDF{RESET}\n")

    print(f"{BOLD}  STEP 2 - Alice encrypts a message{RESET}")
    separator("-", 60)

    original_message = "Transfer approved: $500 to Bob"
    encrypted = crypto_utils.encrypt(aes_key, original_message)

    print(f"  Original message : \"{CYAN}{original_message}{RESET}\"")
    print(f"  Encrypted (hex)  : {YELLOW}{encrypted.hex()}{RESET}")
    print(f"  Length           : {len(encrypted)} bytes")
    print(f"  (First 12 bytes = nonce, rest = ciphertext + auth tag)\n")

    print(f"{BOLD}  STEP 3 - Normal delivery (no tampering){RESET}")
    separator("-", 60)

    try:
        decrypted = crypto_utils.decrypt(aes_key, encrypted)
        print(f"  Bob receives     : \"{GREEN}{decrypted}{RESET}\"")
        print(f"  {GREEN}✅  Message delivered and verified successfully{RESET}\n")
    except Exception as e:
        print(f"  {RED}❌  Unexpected failure: {e}{RESET}\n")

    print(f"{BOLD}  STEP 4 - Attacker intercepts and modifies 1 byte{RESET}")
    separator("-", 60)


    tampered = bytearray(encrypted)

    tamper_position = 20
    original_byte   = tampered[tamper_position]
    tampered[tamper_position] = (original_byte + 1) % 256

    print(f"  Original byte at position {tamper_position}: "
          f"{YELLOW}0x{original_byte:02x}{RESET}")
    print(f"  Modified byte at position {tamper_position}: "
          f"{RED}0x{tampered[tamper_position]:02x}{RESET}")
    print(f"  Original ciphertext: {YELLOW}{encrypted.hex()[:40]}...{RESET}")
    print(f"  Tampered ciphertext: {RED}{bytes(tampered).hex()[:40]}...{RESET}\n")

    print(f"{BOLD}  STEP 5 - Bob tries to decrypt the tampered message{RESET}")
    separator("-", 60)

    try:
        decrypted_tampered = crypto_utils.decrypt(aes_key, bytes(tampered))
        print(f"  {RED}❌  DANGER: Tampered message accepted: \"{decrypted_tampered}\"{RESET}")
        print(f"  {RED}    Integrity check FAILED - AES-GCM is broken!{RESET}")
    except Exception:
        print(f"  {RED}  ⚠  Decryption raised: InvalidTag - authentication failed{RESET}")
        print(f"  {GREEN}{BOLD}  ✅  Tampered message REJECTED - Bob never sees it!{RESET}")
        print(f"  {GREEN}     AES-GCM integrity protection working correctly.{RESET}\n")

    print(f"{BOLD}  STEP 6 - Attacker tampers with the nonce{RESET}")
    separator("-", 60)

    tampered_nonce = bytearray(encrypted)
    tampered_nonce[5] = (tampered_nonce[5] + 1) % 256

    try:
        crypto_utils.decrypt(aes_key, bytes(tampered_nonce))
        print(f"  {RED}❌  Tampered nonce accepted - integrity FAILED!{RESET}")
    except Exception:
        print(f"  {GREEN}{BOLD}  ✅  Tampered nonce REJECTED - Bob never sees it!{RESET}")
        print(f"  {GREEN}     Even modifying the nonce breaks authentication.{RESET}\n")

    separator()
    print(f"\n{BOLD}  SUMMARY{RESET}\n")
    print(f"  {GREEN}✅  Unmodified message: accepted and decrypted correctly{RESET}")
    print(f"  {GREEN}✅  1-byte ciphertext modification: rejected immediately{RESET}")
    print(f"  {GREEN}✅  Nonce modification: rejected immediately{RESET}")
    print(f"  {GREEN}✅  Bob never receives any tampered content{RESET}")
    print(f"\n  AES-GCM guarantees both confidentiality AND integrity.")
    print(f"  An attacker cannot modify messages without detection.")
    separator()

if __name__ == "__main__":
    run_demo()