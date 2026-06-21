import os
import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature



def generate_ecdh_keypair():
    """
    Generates a fresh ephemeral ECDH key pair for this session.
    New key pair every session = Forward Secrecy.
    Private key stays on your machine, public key is shared.
    """
    private_key = X25519PrivateKey.generate()
    public_key  = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """
    Converts a public key object into raw bytes
    so it can be sent over the socket.
    """
    return public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )


def deserialize_public_key(public_bytes):
    """
    Converts raw bytes received from the socket
    back into a usable public key object.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    return X25519PublicKey.from_public_bytes(public_bytes)


def compute_shared_secret(private_key, their_public_key):
    """
    ECDH magic:
    Alice: her private key + Bob's public key   → shared secret
    Bob:   his private key + Alice's public key → same shared secret
    Secret never travels over the network.
    """
    return private_key.exchange(their_public_key)


def derive_aes_key(shared_secret):
    """
    HKDF refines the raw ECDH shared secret into
    a clean 32-byte AES-256 key ready for AES-GCM.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure-chat-key',
    )
    return hkdf.derive(shared_secret)


def encrypt(aes_key, plaintext):
    """
    Encrypts a message using AES-GCM.

    AES-GCM provides TWO guarantees in one operation:
      - Confidentiality: message is unreadable without the key
      - Integrity: any tampering in transit is detected

    nonce = random 12-byte value, unique per message.
    Never reuse a nonce with the same key - it breaks security.
    Nonce is not secret - sent alongside ciphertext.

    Returns: nonce (12 bytes) + ciphertext
    """
    nonce  = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext


def decrypt(aes_key, nonce_and_ciphertext):
    """
    Decrypts a message using AES-GCM.
    First 12 bytes = nonce, rest = ciphertext.
    Automatically verifies integrity - raises error if tampered.
    """
    nonce      = nonce_and_ciphertext[:12]
    ciphertext = nonce_and_ciphertext[12:]
    aesgcm     = AESGCM(aes_key)
    plaintext  = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()



def encrypt_with_counter(aes_key, message, counter):
    """
    Encrypts a message together with its counter value.
    The counter is packed inside the encrypted payload, so it is
    protected by the AES-GCM authentication tag along with the
    message itself.
    """
    payload = json.dumps({"counter": counter, "message": message})
    return encrypt(aes_key, payload)


def decrypt_with_counter(aes_key, encrypted_data, expected_counter):
    """
    Decrypts a message and validates its counter against the
    expected (next) value.

    Returns (message, True, received_counter) if the counter matches.
    Returns (None, False, received_counter) if it does not - this is
    a replay or an out-of-order/duplicate message and must be
    rejected by the caller.
    """
    raw = decrypt(aes_key, encrypted_data)
    payload = json.loads(raw)

    received_counter = payload["counter"]
    message          = payload["message"]

    if received_counter != expected_counter:
        return None, False, received_counter

    return message, True, received_counter



def generate_identity_keypair():
    """
    Generates a long-term identity key pair using Ed25519.

    This is DIFFERENT from the ECDH key pair:
      - ECDH keys  = temporary, new every session (forward secrecy)
      - Identity keys = permanent, represents WHO you are

    Private key = your identity, keep it secret always
    Public key  = share with the other side so they can verify you
    """
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()
    return private_key, public_key


def serialize_identity_public_key(public_key):
    """
    Converts identity public key to raw bytes for sending.
    """
    return public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )


def deserialize_identity_public_key(public_bytes):
    """
    Converts received bytes back into an identity public key object.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(public_bytes)


def sign_public_key(identity_private_key, ecdh_public_bytes):
    """
    Signs the ECDH public key with the identity private key.

    This proves: "I am who I say I am, and this ECDH key is mine."
    Without this signature, anyone could send a fake ECDH key
    and perform a man-in-the-middle attack.

    Returns: signature bytes (64 bytes for Ed25519)
    """
    signature = identity_private_key.sign(ecdh_public_bytes)
    return signature


def verify_signature(identity_public_key, ecdh_public_bytes, signature):
    """
    Verifies the signature on the received ECDH public key.

    If verification passes  → the sender is who they claim to be
    If verification fails   → reject the connection immediately

    Returns: True if valid, False if invalid
    """
    try:
        identity_public_key.verify(signature, ecdh_public_bytes)
        return True
    except InvalidSignature:
        return False