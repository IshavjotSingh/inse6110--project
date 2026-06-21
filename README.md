# Secure Chat

A two-party secure messaging system built in Python for INSE 6110. It sets up an encrypted channel between a client and a server and protects the conversation against eavesdropping, replay, and tampering.

The goal of the project was to put together a working chat prototype using standard cryptographic primitives rather than rolling our own crypto, and to show that the usual security properties (confidentiality, integrity, forward secrecy, replay resistance) actually hold when you test for them.

## How it works

When the client and server connect, they run an X25519 ECDH handshake to agree on a shared secret. That secret is run through HKDF-SHA256 to derive the actual session keys. Each side also has an Ed25519 signing key, so the handshake messages are signed and verified before any session is established.

Once the handshake is done, all messages are encrypted with AES-GCM, which gives both confidentiality and integrity in one step. Every message carries an incrementing counter, and the receiving side checks it. If a counter comes in out of order or repeats, the message is rejected as a replay.

A fresh key pair is generated for every session, so even if one session's keys were somehow exposed, past and future sessions stay safe. That's the forward secrecy part.

## Files

- `crypto_utils.py` — all the cryptographic logic lives here: key exchange, key derivation, signing, and the counter-based encrypt/decrypt functions used by both sides
- `server.py` — the server program; listens for a client and handles the secure session
- `client.py` — the client program; connects to the server and sends encrypted messages
- `forward_secrecy_demo.py` — shows that compromising one session's keys doesn't break other sessions
- `replay_demo.py` — shows that a captured message replayed back to the receiver gets rejected
- `tamper_demo.py` — shows that modifying a ciphertext in transit is detected and the message is dropped

## Requirements

- Python 3
- The `cryptography` library

Install the dependency with:

```
pip install cryptography
```

## Running it

Put all the files in the same folder. The chat needs two terminal windows because the server and client run at the same time.

Start the server first:

```
python server.py
```

Then in a second terminal, start the client:

```
python client.py
```

The server listens on `localhost:9999`. Once the client connects, the handshake runs automatically and you can send messages over the encrypted channel.

## Running the demos

The three demo scripts are standalone, so you just run them directly:

```
python forward_secrecy_demo.py
python replay_demo.py
python tamper_demo.py
```

Each one prints out what it's testing and the result, so you can see the security property holding in practice.

## Author

Ishavjot Singh
MEng Information Systems Security, Concordia University
INSE 6110
