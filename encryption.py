import os
import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC_BYTES = b"WDC14"
KEY_LENGTH = 32
IV_LENGTH = 16
NONCE_LENGTH = 16
SALT_LENGTH = 16
KDF_ITERATIONS = 3
KDF_LANES = 4
KDF_MEMORY_COST = 64*1024


@dataclass
class Metadata:
    METADATA_FORMAT = "<5s3s16s16sIII32s"
    METADATA_SIZE = struct.calcsize(METADATA_FORMAT)

    mode: bytes
    iv_or_nonce: bytes

    kdf_salt: bytes
    kdf_iterations: int
    kdf_lanes: int
    kdf_memory_cost: int
    key_hash: bytes

    def as_bytes(self):
        return struct.pack(
            self.METADATA_FORMAT,
            MAGIC_BYTES,
            self.mode,
            self.iv_or_nonce,
            self.kdf_salt,
            self.kdf_iterations,
            self.kdf_lanes,
            self.kdf_memory_cost,
            self.key_hash
        )

    @classmethod
    def from_file(cls, file):
        unpacked = struct.unpack(cls.METADATA_FORMAT, file.read(cls.METADATA_SIZE))
        magic_bytes = unpacked[0]
        if magic_bytes != MAGIC_BYTES:
            raise ValueError("Invalid magic bytes")
        return cls(*unpacked[1:])



def get_key(password, salt, length, iterations, lanes, memory_cost):
    kdf = Argon2id(
        salt=salt,
        length=length,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost
    )
    return kdf.derive(password.encode())

def encrypt(path: str, password: str, mode: str):
    kdf_settings = (KEY_LENGTH, KDF_ITERATIONS, KDF_LANES, KDF_MEMORY_COST)
    with open(path, "rb") as f:
        data = f.read()
    salt = os.urandom(SALT_LENGTH)
    key = get_key(password, salt, *kdf_settings)

    iv = None
    nonce = None

    if mode == "ecb":
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    elif mode == "cbc":
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
        iv = os.urandom(IV_LENGTH)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif mode == "ctr":
        nonce = os.urandom(NONCE_LENGTH)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    else:
        raise ValueError("Invalid mode")

    encryptor = cipher.encryptor()

    iv_or_nonce = iv or nonce or bytes(16) # 16 zero bytes in case of ecb mode
    metadata = Metadata(mode.encode(), iv_or_nonce, salt,
                        kdf_settings[1], kdf_settings[2], kdf_settings[3],
                        hashlib.sha256(key).digest())

    encrypted_data = metadata.as_bytes() + encryptor.update(data) + encryptor.finalize()

    with open("./result.bin", "wb") as f:
        f.write(encrypted_data)

def decrypt(path: str, password: str):
    with open(path, "rb") as f:
        metadata = Metadata.from_file(f)

        key = get_key(password, metadata.kdf_salt, KEY_LENGTH, metadata.kdf_iterations,
                      metadata.kdf_lanes, metadata.kdf_memory_cost)

        if hashlib.sha256(key).digest() != metadata.key_hash:
            raise ValueError("Incorrect password")

        if metadata.mode == b"ecb": mode = modes.ECB()
        elif metadata.mode == b"cbc": mode = modes.CBC(metadata.iv_or_nonce)
        elif metadata.mode == b"ctr": mode = modes.CTR(metadata.iv_or_nonce)
        else: raise ValueError("Incorrect mode")

        decryptor = Cipher(algorithms.AES(key), mode).decryptor()

        data = decryptor.update(f.read()) + decryptor.finalize()

        if metadata.mode in (b"ecb", b"cbc"):
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(data) + unpadder.finalize()

    with open("./decrypted.bin", "wb") as f:
        f.write(data)


