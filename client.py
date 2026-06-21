import socket
import threading
import crypto_utils

HOST = 'localhost'
PORT = 9999

def receive_messages(sock, aes_key, recv_counter_ref):
    while True:
        try:
            raw_data = sock.recv(4096)
            if not raw_data:
                print("[CLIENT] Server disconnected.")
                break

            print(f"\n[WIRE - ENCRYPTED]: {raw_data.hex()[:40]}...")

            message, valid, received_counter = crypto_utils.decrypt_with_counter(
                aes_key, raw_data, recv_counter_ref[0]
            )

            if not valid:
                print(
                    f"[CLIENT] ⚠  Replay attack detected! "
                    f"Expected counter {recv_counter_ref[0]}, got {received_counter}"
                )
                continue

            print(f"[SERVER] (counter={recv_counter_ref[0]}): {message}")
            recv_counter_ref[0] += 1

        except Exception:
            print("[CLIENT] Server disconnected.")
            break

def perform_handshake(sock):
    print("\n[CLIENT] - Starting Handshake -")

    identity_private, identity_public = crypto_utils.generate_identity_keypair()
    identity_public_bytes = crypto_utils.serialize_identity_public_key(identity_public)

    server_identity_bytes  = sock.recv(1024)
    server_identity_pubkey = crypto_utils.deserialize_identity_public_key(server_identity_bytes)
    print(f"[CLIENT] Server identity received: {server_identity_bytes.hex()[:24]}...")

    sock.send(identity_public_bytes)
    print(f"[CLIENT] Identity key sent:     {identity_public_bytes.hex()[:24]}...")

    ecdh_private, ecdh_public = crypto_utils.generate_ecdh_keypair()
    ecdh_public_bytes = crypto_utils.serialize_public_key(ecdh_public)

    server_data       = sock.recv(1024)
    server_ecdh_bytes = server_data[:32]
    server_signature  = server_data[32:]

    print("[CLIENT] Verifying server signature...")
    valid = crypto_utils.verify_signature(
        server_identity_pubkey, server_ecdh_bytes, server_signature
    )

    if not valid:
        print("[CLIENT] ❌ SIGNATURE INVALID - Rejecting connection!")
        sock.close()
        return None

    print("[CLIENT] ✅ Signature verified - server identity confirmed!")

    signature = crypto_utils.sign_public_key(identity_private, ecdh_public_bytes)
    sock.send(ecdh_public_bytes + signature)
    print(f"[CLIENT] ECDH key + signature sent: {ecdh_public_bytes.hex()[:24]}...")

    server_ecdh_pubkey = crypto_utils.deserialize_public_key(server_ecdh_bytes)
    shared_secret      = crypto_utils.compute_shared_secret(ecdh_private, server_ecdh_pubkey)
    aes_key            = crypto_utils.derive_aes_key(shared_secret)

    print(f"[CLIENT] AES-GCM key: {aes_key.hex()}")
    print("[CLIENT] - Handshake Complete - Channel Secured -\n")

    return aes_key

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("=" * 55)
    print("  SECURE CHAT CLIENT")
    print("  ECDH + HKDF + AES-GCM + Signatures + Replay Protection")
    print("=" * 55)
    print(f"[CLIENT] Connecting to {HOST}:{PORT}...")

    client_socket.connect((HOST, PORT))
    print(f"[CLIENT] Connected!")
    print("-" * 55)

    aes_key = perform_handshake(client_socket)
    if aes_key is None:
        return

    print("[CLIENT] Type a message and press Enter. Type 'quit' to exit.")
    print("=" * 55)

    send_counter = [0]
    recv_counter = [0]

    receive_thread = threading.Thread(
        target=receive_messages,
        args=(client_socket, aes_key, recv_counter)
    )
    receive_thread.daemon = True
    receive_thread.start()

    while True:
        try:
            message = input()
            if message.lower() == 'quit':
                print("[CLIENT] Closing connection.")
                break
            encrypted = crypto_utils.encrypt_with_counter(aes_key, message, send_counter[0])
            print(f"[WIRE - ENCRYPTED]: {encrypted.hex()[:40]}...")
            client_socket.send(encrypted)
            send_counter[0] += 1
        except (KeyboardInterrupt, EOFError):
            print("\n[CLIENT] Shutting down.")
            break
        except Exception:
            break

    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        client_socket.close()
    except Exception:
        pass

    print("[CLIENT] Connection closed cleanly.")

if __name__ == "__main__":
    start_client()