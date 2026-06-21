import socket
import threading
import crypto_utils

HOST = 'localhost'
PORT = 9999

def receive_messages(conn, aes_key, recv_counter_ref):
    while True:
        try:
            raw_data = conn.recv(4096)
            if not raw_data:
                print("[SERVER] Client disconnected.")
                break

            print(f"\n[WIRE - ENCRYPTED]: {raw_data.hex()[:40]}...")

            message, valid, received_counter = crypto_utils.decrypt_with_counter(
                aes_key, raw_data, recv_counter_ref[0]
            )

            if not valid:
                print(
                    f"[SERVER] ⚠  Replay attack detected! "
                    f"Expected counter {recv_counter_ref[0]}, got {received_counter}"
                )
                continue

            print(f"[CLIENT] (counter={recv_counter_ref[0]}): {message}")
            recv_counter_ref[0] += 1

        except Exception as e:
            print(f"[SERVER] Error: {e}")
            break


def perform_handshake(conn):
    print("\n[SERVER] - Starting Handshake -")

    identity_private, identity_public = crypto_utils.generate_identity_keypair()
    identity_public_bytes = crypto_utils.serialize_identity_public_key(identity_public)


    conn.send(identity_public_bytes)
    print(f"[SERVER] Identity public key sent: {identity_public_bytes.hex()[:24]}...")

    client_identity_bytes  = conn.recv(1024)
    client_identity_pubkey = crypto_utils.deserialize_identity_public_key(client_identity_bytes)
    print(f"[SERVER] Client identity key received: {client_identity_bytes.hex()[:24]}...")

    ecdh_private, ecdh_public = crypto_utils.generate_ecdh_keypair()
    ecdh_public_bytes = crypto_utils.serialize_public_key(ecdh_public)

    signature = crypto_utils.sign_public_key(identity_private, ecdh_public_bytes)

    conn.send(ecdh_public_bytes + signature)
    print(f"[SERVER] ECDH key + signature sent: {ecdh_public_bytes.hex()[:24]}...")

    client_data            = conn.recv(1024)
    client_ecdh_bytes      = client_data[:32]   
    client_signature       = client_data[32:]   
    print("[SERVER] Verifying client signature...")
    valid = crypto_utils.verify_signature(
        client_identity_pubkey,
        client_ecdh_bytes,
        client_signature
    )

    if not valid:
        print("[SERVER] ❌ SIGNATURE INVALID — Rejecting connection!")
        conn.close()
        return None

    print("[SERVER] ✅ Signature verified — client identity confirmed!")

    client_ecdh_pubkey = crypto_utils.deserialize_public_key(client_ecdh_bytes)
    shared_secret      = crypto_utils.compute_shared_secret(ecdh_private, client_ecdh_pubkey)
    aes_key            = crypto_utils.derive_aes_key(shared_secret)

    print(f"[SERVER] Shared secret: {shared_secret.hex()[:24]}...")
    print(f"[SERVER] AES-GCM key:   {aes_key.hex()}")
    print("[SERVER] - Handshake Complete - Channel Secured -\n")

    return aes_key

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print("=" * 55)
    print("  SECURE CHAT SERVER — Phase 4 (Full Security)")
    print("  ECDH + HKDF + AES-GCM + Digital Signatures")
    print("=" * 55)
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    print("[SERVER] Waiting for client...")

    conn, address = server_socket.accept()
    print(f"[SERVER] Client connected: {address}")
    print("-" * 55)

    # Full handshake with identity verification
    aes_key = perform_handshake(conn)

    if aes_key is None:
        print("[SERVER] Handshake failed. Shutting down.")
        return

    print("[SERVER] Type a message and press Enter.")
    print("=" * 55)

    send_counter = [0]
    recv_counter = [0]

    # Start receive thread
    receive_thread = threading.Thread(
        target=receive_messages,
        args=(conn, aes_key, recv_counter)
    )
    receive_thread.daemon = True
    receive_thread.start()

    while True:
        try:
            message = input()
            if message.lower() == 'quit':
                print("[SERVER] Closing connection.")
                break
            encrypted = crypto_utils.encrypt_with_counter(aes_key, message, send_counter[0])
            print(f"[WIRE - ENCRYPTED]: {encrypted.hex()[:40]}...")
            conn.send(encrypted)
            send_counter[0] += 1
        except Exception as e:
            print(f"[SERVER] Error: {e}")
            break

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()