import crypto_utils

# Terminal colors
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
    print(f"{BOLD}  REPLAY ATTACK PREVENTION DEMONSTRATION{RESET}")
    print(f"  Counter-Based Message Authentication")
    print(f"  INSE 6110 — Concordia University")
    separator()

    print(f"""
  {BOLD}What is a Replay Attack?{RESET}
  An attacker captures a valid encrypted message
  and re-sends it later. They cannot read it, but
  they can cause damage by replaying it repeatedly.

  Defence: every message contains an encrypted counter.
  The receiver only accepts the NEXT expected counter.
  Any replayed message has a stale counter — rejected.
    """)

    
    print(f"{BOLD}  SETUP - Alice and Bob establish a session key{RESET}")
    separator("-", 60)

    alice_priv, alice_pub = crypto_utils.generate_ecdh_keypair()
    bob_priv,   bob_pub   = crypto_utils.generate_ecdh_keypair()

    shared = crypto_utils.compute_shared_secret(
        alice_priv,
        crypto_utils.deserialize_public_key(
            crypto_utils.serialize_public_key(bob_pub)
        )
    )
    aes_key = crypto_utils.derive_aes_key(shared)
    print(f"  Session key: {GREEN}{aes_key.hex()[:32]}...{RESET}")
    print(f"  {GREEN}✅  Shared key established{RESET}\n")

    
    print(f"{BOLD}  STEP 1 - Normal conversation (counters 0, 1, 2){RESET}")
    separator("-", 60)

    messages = [
        "Hello Bob!",
        "Transfer approved: $500 to Bob",
        "See you tomorrow"
    ]

    encrypted_messages = []
    bob_expected_counter = 0

    for i, msg in enumerate(messages):
        
        enc = crypto_utils.encrypt_with_counter(aes_key, msg, i)
        encrypted_messages.append(enc)

        
        decrypted, valid, counter = crypto_utils.decrypt_with_counter(
            aes_key, enc, bob_expected_counter
        )

        if valid:
            print(f"  Msg {i} | Counter: {CYAN}{counter}{RESET} | "
                  f"Content: \"{GREEN}{decrypted}{RESET}\"")
            print(f"         | {GREEN}✅  Accepted — counter matches expected{RESET}")
            bob_expected_counter += 1
        else:
            print(f"  Msg {i} | {RED}❌  Rejected{RESET}")

    
    print(f"\n{BOLD}  STEP 2 - Attacker replays Message 1 (the $500 transfer){RESET}")
    separator("-", 60)

    print(f"  Attacker re-sends: \"{YELLOW}Transfer approved: $500 to Bob{RESET}\"")
    print(f"  Replayed counter : {RED}1{RESET} (stale - Bob expects {bob_expected_counter})\n")

    replayed_enc = encrypted_messages[1]
    decrypted, valid, counter = crypto_utils.decrypt_with_counter(
        aes_key, replayed_enc, bob_expected_counter
    )

    if valid:
        print(f"  {RED}❌  DANGER: Replay accepted: \"{decrypted}\"{RESET}")
        print(f"  {RED}    Replay protection FAILED!{RESET}")
    else:
        print(f"  Bob received counter : {RED}{counter}{RESET}")
        print(f"  Bob expected counter : {GREEN}{bob_expected_counter}{RESET}")
        print(f"  {GREEN}{BOLD}  ✅  Replay REJECTED — counter mismatch detected!{RESET}")
        print(f"  {GREEN}     $500 transfer was NOT processed again.{RESET}")

    
    print(f"\n{BOLD}  STEP 3 - Attacker replays Message 0 (Hello Bob!){RESET}")
    separator("-", 60)

    replayed_enc0 = encrypted_messages[0]
    decrypted0, valid0, counter0 = crypto_utils.decrypt_with_counter(
        aes_key, replayed_enc0, bob_expected_counter
    )

    if valid0:
        print(f"  {RED}❌  Replay accepted - protection FAILED!{RESET}")
    else:
        print(f"  Bob received counter : {RED}{counter0}{RESET}")
        print(f"  Bob expected counter : {GREEN}{bob_expected_counter}{RESET}")
        print(f"  {GREEN}{BOLD}  ✅  Replay REJECTED - counter mismatch detected!{RESET}")


    print(f"\n{BOLD}  STEP 4 - Conversation continues normally{RESET}")
    separator("-", 60)

    next_msg = "Thanks for the payment confirmation!"
    enc_next = crypto_utils.encrypt_with_counter(aes_key, next_msg, bob_expected_counter)
    dec_next, valid_next, cnt_next = crypto_utils.decrypt_with_counter(
        aes_key, enc_next, bob_expected_counter
    )

    if valid_next:
        print(f"  Msg {bob_expected_counter} | Counter: {CYAN}{cnt_next}{RESET} | "
              f"Content: \"{GREEN}{dec_next}{RESET}\"")
        print(f"         | {GREEN}✅  Accepted — legitimate message passes through{RESET}")


    separator()
    print(f"\n{BOLD}  SUMMARY{RESET}\n")
    print(f"  {GREEN}✅  Legitimate messages accepted in correct order{RESET}")
    print(f"  {GREEN}✅  Replayed $500 transfer rejected - money safe{RESET}")
    print(f"  {GREEN}✅  All replayed messages rejected by counter check{RESET}")
    print(f"  {GREEN}✅  Conversation resumes normally after attack attempt{RESET}")
    print(f"\n  Counter is inside the encrypted payload - attacker")
    print(f"  cannot modify it without breaking AES-GCM integrity.")
    separator()

if __name__ == "__main__":
    run_demo()