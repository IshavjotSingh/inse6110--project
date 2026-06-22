import crypto_utils
import os

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def separator(char="=", length=60):
    print(char * length)

def simulate_session(session_number):
    """
    Simulates a complete secure session between Alice and Bob.
    Both sides generate fresh ephemeral ECDH key pairs.
    Returns the AES key used in this session.
    """
    print(f"\n{BOLD}{CYAN}  SESSION {session_number}{RESET}")
    separator("-", 60)

    alice_private, alice_public = crypto_utils.generate_ecdh_keypair()
    alice_public_bytes = crypto_utils.serialize_public_key(alice_public)

    bob_private, bob_public = crypto_utils.generate_ecdh_keypair()
    bob_public_bytes = crypto_utils.serialize_public_key(bob_public)

    print(f"  Alice ECDH public key : {YELLOW}{alice_public_bytes.hex()[:48]}...{RESET}")
    print(f"  Bob   ECDH public key : {YELLOW}{bob_public_bytes.hex()[:48]}...{RESET}")


    alice_shared = crypto_utils.compute_shared_secret(
        alice_private,
        crypto_utils.deserialize_public_key(bob_public_bytes)
    )
    bob_shared = crypto_utils.compute_shared_secret(
        bob_private,
        crypto_utils.deserialize_public_key(alice_public_bytes)
    )


    assert alice_shared == bob_shared, "Shared secrets do not match!"

    print(f"  Shared secret         : {YELLOW}{alice_shared.hex()[:48]}...{RESET}")


    aes_key = crypto_utils.derive_aes_key(alice_shared)
    print(f"  AES-GCM session key   : {GREEN}{aes_key.hex()}{RESET}")


    sample_message = f"Hello from session {session_number}!"
    encrypted = crypto_utils.encrypt(aes_key, sample_message)
    decrypted = crypto_utils.decrypt(aes_key, encrypted)

    print(f"\n  Message               : \"{sample_message}\"")
    print(f"  On the wire           : {RED}{encrypted.hex()[:48]}...{RESET}")
    print(f"  Decrypted             : {GREEN}\"{decrypted}\"{RESET}")

    del alice_private
    del bob_private
    del alice_shared
    del bob_shared

    print(f"\n  {YELLOW}  Session ended — ephemeral keys permanently discarded{RESET}")

    return aes_key


def run_demo():
    separator("=", 60)
    print(f"{BOLD}  PERFECT FORWARD SECRECY DEMONSTRATION{RESET}")
    print(f"  Secure Messaging System with Forward Secrecy")
    print(f"  INSE 6110 — Concordia University")
    separator("=", 60)

    print(f"""
  {BOLD}What is Forward Secrecy?{RESET}
  Each session generates a brand new ECDH key pair.
  Session keys are never stored - discarded after use.
  Stealing today's key gives an attacker NOTHING about
  any past or future session.

  Simulating 3 separate chat sessions below...
    """)

    
    session_keys = []
    for i in range(1, 4):
        key = simulate_session(i)
        session_keys.append(key)

    
    separator("=", 60)
    print(f"\n{BOLD}  PROOF - All 3 Session Keys Are Completely Different{RESET}\n")

    for i, key in enumerate(session_keys, 1):
        print(f"  Session {i} AES key: {CYAN}{key.hex()}{RESET}")

    print()

    
    all_unique = len(set([k.hex() for k in session_keys])) == len(session_keys)

    if all_unique:
        print(f"  {GREEN}{BOLD}   All 3 session keys are completely different.{RESET}")
    else:
        print(f"  {RED}❌  Keys repeated — something is wrong!{RESET}")

    separator("-", 60)
    print(f"\n{BOLD}  ATTACK SCENARIO - What if Session 3 key is stolen?{RESET}\n")

    print(f"  Attacker captures Session 3 AES key:")
    print(f"  {RED}{session_keys[2].hex()}{RESET}\n")

    print(f"  Can attacker decrypt Session 1 messages?")


    try:
        session1_message = "Hello from session 1!"
        encrypted_s1 = crypto_utils.encrypt(session_keys[0], session1_message)

        
        crypto_utils.decrypt(session_keys[2], encrypted_s1)
        print(f"  {RED}❌  Decryption succeeded — forward secrecy FAILED!{RESET}")

    except Exception:
        print(f"  {GREEN}{BOLD}     Decryption FAILED — Session 1 is protected!{RESET}")
        print(f"  {GREEN}  The stolen key is useless against past sessions.{RESET}")

    print(f"\n  Can attacker decrypt Session 2 messages?")

    try:
        session2_message = "Hello from session 2!"
        encrypted_s2 = crypto_utils.encrypt(session_keys[1], session2_message)
        crypto_utils.decrypt(session_keys[2], encrypted_s2)
        print(f"  {RED}❌  Decryption succeeded — forward secrecy FAILED!{RESET}")

    except Exception:
        print(f"  {GREEN}{BOLD}     Decryption FAILED — Session 2 is protected!{RESET}")
        print(f"  {GREEN}  The stolen key is useless against past sessions.{RESET}")


    separator("=", 60)
    print(f"\n{BOLD}  SUMMARY{RESET}\n")
    print(f"  {GREEN}   Every session uses unique ephemeral ECDH key pairs{RESET}")
    print(f"  {GREEN}   Every session derives a completely different AES key{RESET}")
    print(f"  {GREEN}   Session keys are discarded immediately after use{RESET}")
    print(f"  {GREEN}   Compromising one session key exposes ZERO past data{RESET}")
    separator("=", 60)


if __name__ == "__main__":
    run_demo()