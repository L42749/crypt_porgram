# secure_comms/key_exchange.py
from Crypto.PublicKey import ECC, RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes
import random
from datetime import datetime

# DH 參數 (需要與 sender/receiver 相同)
DH_PRIME = 28164586923
DH_GENERATOR = 3

def get_timestamp():
    """獲取目前時間的時間戳記。"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

# ECC
def generate_ecc_keys():
    """生成 ECC 金鑰對 (使用 NIST P-256 曲線)。"""
    key = ECC.generate(curve='P-256')
    return key, key.public_key()

def export_ecc_public_key(public_key):
    """匯出 ECC 公鑰為 PEM 格式。"""
    return public_key.export_key(format='PEM')

def import_ecc_public_key(pem_public_key):
    """從 PEM 格式匯入 ECC 公鑰。"""
    return ECC.import_key(pem_public_key.encode('utf-8'))

def perform_ecc_key_exchange(private_key, remote_public_key):
    """執行 ECC 金鑰交換並獲取共享秘密。"""
    point2 = remote_public_key.pointQ
    shared_point = point2 * private_key.d
    return SHA256.new(shared_point.x.to_bytes(32, 'big')).digest()

# RSA
def generate_rsa_keys():
    """生成 RSA 金鑰對。"""
    key = RSA.generate(2048)
    return key, key.publickey()

def export_rsa_public_key(public_key):
    """匯出 RSA 公鑰為 PEM 格式。"""
    return public_key.exportKey(format='PEM').decode('utf-8')

def import_rsa_public_key(pem_public_key):
    """從 PEM 格式匯入 RSA 公鑰。"""
    return RSA.importKey(pem_public_key.encode('utf-8'))

# DH
def generate_dh_private_key():
    """生成 DH 私鑰。"""
    return random.randint(2, DH_PRIME - 2)

def generate_dh_public_key(private_key):
    """生成 DH 公鑰。"""
    return pow(DH_GENERATOR, private_key, DH_PRIME)

def compute_dh_shared_secret(private_key, remote_public_key):
    """計算 DH 共享秘密。"""
    return pow(remote_public_key, private_key, DH_PRIME)
