# attacker/attacker.py
import socket
import sys
import traceback
import json
import base64
from secure_comms import crypto_utils, network_utils # Import network_utils for receive_json_data

ATTACKER_DEBUG_MODE = False # 預設為 False，將由 Sender 控制
RESTART_SESSION_SIGNAL = {'control': 'restart_session'} # 會話重置信號
SHUTDOWN_SIGNAL = {'control': 'shutdown'} # 關閉信號

def attacker_debug_print(message):
    global ATTACKER_DEBUG_MODE
    if ATTACKER_DEBUG_MODE:
        timestamp = crypto_utils.get_timestamp()
        print(f"[{timestamp}] [ATTACKER DEBUG] {message}")

def attacker_print_info(message):
    timestamp = crypto_utils.get_timestamp()
    print(f"[{timestamp}] [ATTACKER] {message}")

def handle_sender_forward(conn, addr):
    """處理來自 sender 轉發的資料。
       返回 True 表示需要重新啟動會話（接受新連接），False 表示正常結束。
    """
    global ATTACKER_DEBUG_MODE # 允許修改全局 DEBUG_MODE
    attacker_print_info(f"Sender {addr} connected for forwarding.")
    simple_aes_key = crypto_utils.generate_simple_key() # Attacker's hardcoded key for "none" mode
    attacker_debug_print(f"Attacker's simple AES key: {simple_aes_key.hex()}")

    sender_id = "unknown" # Default sender ID
    should_restart_session = False # 新增旗標，用於控制是否重啟會話

    try:
        while True:
            forwarded_data = network_utils.receive_json_data(conn)
            if not forwarded_data:
                attacker_print_info(f"Sender {addr} disconnected from forwarding channel.")
                break # 連接斷開，跳出迴圈
            
            # --- 處理會話重置信號 ---
            if forwarded_data == RESTART_SESSION_SIGNAL:
                attacker_print_info("Received session restart signal from sender. Reinitializing attacker state.")
                should_restart_session = True # 設定旗標為 True
                break # 跳出迴圈，讓 finally 區塊處理關閉和返回值
            # --- 處理關閉信號 ---
            if forwarded_data == SHUTDOWN_SIGNAL:
                attacker_print_info("Received shutdown signal from sender. Terminating attacker.")
                return False # 直接返回 False，表示終止程式
            # --- 結束新增 ---

            attacker_debug_print(f"Received forwarded data: {json.dumps(forwarded_data)}")

            # Check if it's initial sender info
            if 'identity' in forwarded_data and 'ecc_public_key' in forwarded_data:
                sender_id = forwarded_data.get('identity', 'unknown')
                # --- 更新 Attacker 的 DEBUG_MODE ---
                ATTACKER_DEBUG_MODE = forwarded_data.get('debug_mode', False)
                network_utils.set_debug_mode(ATTACKER_DEBUG_MODE) # 同步 network_utils 的 debug 模式
                attacker_print_info(f"Received initial info from sender: {sender_id}. Attacker Debug Mode: {'ON' if ATTACKER_DEBUG_MODE else 'OFF'}")
                # --- 結束更新 ---
                attacker_debug_print(f"Sender ECC Public Key: {forwarded_data.get('ecc_public_key', '')[:50]}...")
                attacker_debug_print(f"Sender RSA Public Key: {forwarded_data.get('rsa_public_key', '')[:50]}...")
                continue # Process next data

            # Check if it's receiver's public key info
            if 'identity' in forwarded_data and 'rsa_public_key' in forwarded_data and forwarded_data.get('identity') == 'receiver_bob':
                attacker_print_info(f"Received receiver's public keys.")
                attacker_debug_print(f"Receiver ECC Public Key: {forwarded_data.get('ecc_public_key', '')[:50]}...")
                attacker_debug_print(f"Receiver RSA Public Key: {forwarded_data.get('rsa_public_key', '')[:50]}...")
                continue # Process next data

            # Check if it's key exchange method
            if 'key_exchange' in forwarded_data:
                key_exchange_method = forwarded_data['key_exchange']
                attacker_print_info(f"Observed key exchange method: {key_exchange_method}")
                continue # Process next data

            # Check if it's encrypted AES key (RSA encrypted)
            if 'encrypted_aes_key' in forwarded_data:
                encrypted_aes_key_b64 = forwarded_data['encrypted_aes_key']
                attacker_print_info(f"Observed RSA encrypted AES key.")
                attacker_debug_print(f"Encrypted AES key (Base64): {encrypted_aes_key_b64[:50]}...")
                # Attacker cannot decrypt RSA encrypted key without receiver's private key
                continue # Process next data

            # Check if it's DH public key exchange
            if 'dh_public_key' in forwarded_data:
                dh_public_key = forwarded_data['dh_public_key']
                attacker_print_info(f"Observed DH public key: {dh_public_key}")
                # Attacker cannot compute shared secret without private key
                continue # Process next data

            # Assume it's an encrypted message
            mode = forwarded_data.get('mode')
            iv_hex = forwarded_data.get('iv')
            nonce_hex = forwarded_data.get('nonce')
            ciphertext_hex = forwarded_data.get('ciphertext')
            tag_hex = forwarded_data.get('tag')
            associated_data_str = forwarded_data.get('associated_data', '')
            associated_data = associated_data_str.encode('utf-8')

            if mode and ciphertext_hex:
                attacker_print_info(f"Attempting to decrypt message (Mode: {mode}) from {sender_id}...")
                # Attacker attempts decryption using its simple_aes_key
                plaintext = crypto_utils.decrypt_aes(mode, simple_aes_key, ciphertext_hex, iv_hex, nonce_hex, tag_hex, associated_data)
                
                if plaintext:
                    attacker_print_info(f"SUCCESS: Decrypted message from {sender_id}: {plaintext}")
                else:
                    attacker_print_info(f"FAILED: Could not decrypt message (likely due to strong encryption or key mismatch).")
            else:
                attacker_print_info("Received incomplete or unrecognized data for decryption attempt.")

    except Exception as e:
        attacker_print_info(f"Error handling forwarded data: {e}")
        traceback.print_exc()
        should_restart_session = False # 發生錯誤時，不重啟會話
    finally:
        conn.close() # 確保連接被關閉
        attacker_print_info(f"Forwarding channel from {addr} closed.")
        return should_restart_session # 返回旗標的值，決定是否重啟會話

def run_attacker(attacker_host='127.0.0.1', attacker_port=12347):
    """啟動 attacker 並監聽 sender 轉發的資料。"""
    attacker_print_info("Starting attacker...")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((attacker_host, attacker_port))
        s.listen(5) # Allow multiple senders to connect for forwarding
        attacker_print_info(f"Listening for sender forwarding on {attacker_host}:{attacker_port}")
        while True: # Loop to continuously accept new forwarding connections
            conn, addr = s.accept()
            # In a real scenario, use threading for concurrent connections
            # import threading
            # client_thread = threading.Thread(target=handle_sender_forward, args=(conn, addr))
            # client_thread.start()
            should_continue_listening = handle_sender_forward(conn, addr) # Handle sequentially for now
            if not should_continue_listening: # If handle_sender_forward returns False (shutdown), break to stop listening
                break
    except Exception as e:
        attacker_print_info(f"Attacker error: {e}")
        traceback.print_exc()
    finally:
        if s:
            s.close()
        attacker_print_info("Attacker stopped.")

if __name__ == "__main__":
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Initial setup of network_utils debug mode (can be overridden by sender's info)
    network_utils.set_debug_mode(ATTACKER_DEBUG_MODE) 
    
    run_attacker(attacker_host='127.0.0.1', attacker_port=12347)
