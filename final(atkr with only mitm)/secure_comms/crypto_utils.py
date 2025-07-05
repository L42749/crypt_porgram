# secure_comms/crypto_utils.py
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Util.number import long_to_bytes
import os
import base64
import traceback
from datetime import datetime

def get_timestamp():
    """獲取目前時間的時間戳記。"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def generate_aes_key(secret):
    """從共享密鑰生成 AES 金鑰。"""
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(secret)
    return derived_key

def generate_simple_key(length=32):
    """生成一個簡單的隨機 AES 金鑰。"""
    # Note: This key is hardcoded for simplicity in "none" mode.
    # In a real scenario, this would be insecure.
    return b'this_is_a_32_byte_key_for___test'[:length]


def rsa_encrypt(public_key, plaintext):
    """使用 RSA 公鑰加密資料。"""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)

def rsa_decrypt(private_key, ciphertext):
    """使用 RSA 私鑰解密資料。"""
    cipher = PKCS1_OAEP.new(private_key)
    try:
        return cipher.decrypt(ciphertext)
    except ValueError:
        return None

def encrypt_aes(mode_str, key, plaintext, associated_data=None):
    """使用指定的 AES 模式加密資料。"""
    plaintext_bytes = plaintext.encode('utf-8')
    iv = os.urandom(16)
    nonce = os.urandom(12)
    tag = None
    ciphertext = None

    if mode_str.upper() == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        iv = None
    elif mode_str.upper() == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    elif mode_str.upper() == 'CTR':
        nonce = os.urandom(8) # Generate 8-byte nonce for CTR
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext_bytes)
        iv = nonce # Now 'iv' will hold the CTR nonce
    elif mode_str.upper() == 'GCM':
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            cipher.update(associated_data)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        iv = nonce # GCM uses nonce, let's be consistent in return
    else:
        print(f"Unknown AES mode: {mode_str}")
        return None, None, None

    return ciphertext, iv, tag

def decrypt_aes(mode_str, key, ciphertext_hex, iv_hex, nonce_hex, tag_hex, associated_data=None):
    """使用指定的 AES 模式解密資料。"""
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    iv = bytes.fromhex(iv_hex) if iv_hex else None
    nonce = bytes.fromhex(nonce_hex) if nonce_hex else None
    tag = bytes.fromhex(tag_hex) if tag_hex else None

    try:
        if mode_str.upper() == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size).decode('utf-8')
            return plaintext
        elif mode_str.upper() == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size).decode('utf-8')
            return plaintext
        elif mode_str.upper() == 'CTR':
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
            plaintext_bytes = cipher.decrypt(ciphertext_bytes)
            try:
                plaintext = plaintext_bytes.decode('utf-8')
            except UnicodeDecodeError:
                print("[CRYPTO] CTR: Warning - Could not decode as UTF-8. Returning raw bytes (hex).")
                plaintext = plaintext_bytes.hex()
            return plaintext
        elif mode_str.upper() == 'GCM':
            if nonce and tag:
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                if associated_data:
                    cipher.update(associated_data)
                plaintext = cipher.decrypt_and_verify(ciphertext_bytes, tag).decode('utf-8')
                return plaintext
            else:
                print("Error: Nonce or tag missing for GCM decryption.")
                return None
        else:
            print(f"Unknown AES mode: {mode_str}")
            return None
    except ValueError as e:
        print(f"[CRYPTO] Error in decrypt_aes ({mode_str}): {e}")
        traceback.print_exc()
        return None
    except Exception as e:
        print(f"[CRYPTO] An unexpected error occurred during decryption ({mode_str}): {e}")
        traceback.print_exc()
        return None

def encode_base64(data):
    """將位元組資料編碼為 Base64 字串。"""
    return base64.b64encode(data).decode('utf-8')

def decode_base64(s):
    """將 Base64 字串解碼為位元組資料。"""
    return base64.b64decode(s.encode('utf-8'))
