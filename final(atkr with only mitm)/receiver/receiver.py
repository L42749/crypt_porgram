# receiver/receiver.py
import socket
import sys
import traceback
from secure_comms import crypto_utils, key_exchange, network_utils
from Crypto.Util.number import long_to_bytes

DEBUG_MODE = False
RESTART_SESSION_SIGNAL = {'control': 'restart_session'} # 會話重置信號
SHUTDOWN_SIGNAL = {'control': 'shutdown'} # 關閉信號

def debug_print(message):
    global DEBUG_MODE
    if DEBUG_MODE:
        timestamp = crypto_utils.get_timestamp()
        print(f"[{timestamp}] [DEBUG] Receiver: {message}")

def print_info(message):
    timestamp = crypto_utils.get_timestamp()
    print(f"[{timestamp}] Receiver: {message}")

def handle_client(conn, addr):
    """處理來自 sender 的連線。
       返回 True 表示會話已結束（例如 sender 斷開連接或發送關閉信號），False 表示正常退出。
    """
    global DEBUG_MODE
    print_info(f"Connected by {addr}")

    receiver_id = "receiver_bob"
    receiver_ecc_private, receiver_ecc_public = key_exchange.generate_ecc_keys()
    receiver_rsa_private, receiver_rsa_public = key_exchange.generate_rsa_keys()
    receiver_ecc_public_pem = key_exchange.export_ecc_public_key(receiver_ecc_public)
    receiver_rsa_public_pem = key_exchange.export_rsa_public_key(receiver_rsa_public)

    sender_info = network_utils.receive_json_data(conn)
    if sender_info:
        # --- 處理關閉信號 (如果 sender 在初始階段就發送) ---
        if sender_info == SHUTDOWN_SIGNAL:
            print_info("Received shutdown signal from sender during initial handshake. Terminating receiver.")
            conn.close()
            return False # Signal run_receiver to stop listening and exit
        # --- 結束處理 ---

        sender_ecc_public_pem = sender_info.get("ecc_public_key")
        sender_rsa_public_pem = sender_info.get("rsa_public_key")
        sender_id = sender_info.get("identity")
        sender_debug_mode = sender_info.get("debug_mode", False)
        
        # Receiver's DEBUG_MODE is controlled by sender's debug_mode
        DEBUG_MODE = sender_debug_mode
        network_utils.set_debug_mode(DEBUG_MODE) # Set network_utils's debug mode

        debug_print(f"Sender's debug mode is {'ON' if DEBUG_MODE else 'OFF'}")
        # 1. 只有在 debug mode 時才顯示接收到的公鑰
        debug_print(f"Received sender's ECC public key: {sender_ecc_public_pem[:50]}...")
        debug_print(f"Received sender's RSA public key: {sender_rsa_public_pem[:50]}...")

        response_data = {
            "ecc_public_key": receiver_ecc_public_pem,
            "rsa_public_key": receiver_rsa_public_pem,
            "identity": receiver_id
        }
        network_utils.send_json_data(conn, response_data)
        print_info("Public keys sent.")

        while True: # Outer loop to handle key exchange and session restarts
            aes_key = None
            
            print_info("Waiting for key exchange method from Sender...") # Added log
            key_exchange_info = network_utils.receive_json_data(conn)
            if not key_exchange_info:
                print_info("Connection closed by sender during key exchange setup.")
                conn.close() # 在這裡關閉連接
                return False # Signal run_receiver to stop listening and exit
            
            # --- 處理會話重置信號 ---
            if key_exchange_info == RESTART_SESSION_SIGNAL:
                print_info("Received session restart signal from sender. Reinitializing session state.")
                conn.close() # 關閉當前連接，因為 sender 會重新連接
                return True # Signal run_receiver to accept a new connection
            # --- 處理關閉信號 ---
            if key_exchange_info == SHUTDOWN_SIGNAL:
                print_info("Received shutdown signal from sender. Terminating receiver.")
                conn.close()
                return False # Signal run_receiver to stop listening and exit
            # --- 結束新增 ---

            if 'key_exchange' not in key_exchange_info:
                print_info("Invalid key exchange info received. Waiting for valid info.")
                continue # Wait for valid key exchange info

            key_exchange_method = key_exchange_info['key_exchange']
            debug_print(f"Key exchange method received: {key_exchange_method}")

            if key_exchange_method == 'rsa':
                print_info("Waiting for RSA encrypted AES key...") # Added log
                encrypted_aes_key_b64_info = network_utils.receive_json_data(conn)
                if not encrypted_aes_key_b64_info: # Check for disconnection after key exchange method
                    print_info("Connection closed by sender during RSA key reception.")
                    conn.close() # 在這裡關閉連接
                    return False
                # --- 處理關閉信號 (如果 sender 在 RSA 金鑰傳輸中發送) ---
                if encrypted_aes_key_b64_info == SHUTDOWN_SIGNAL:
                    print_info("Received shutdown signal from sender during RSA key reception. Terminating receiver.")
                    conn.close()
                    return False
                # --- 結束處理 ---
                if encrypted_aes_key_b64_info and 'encrypted_aes_key' in encrypted_aes_key_b64_info:
                    encrypted_aes_key = network_utils.decode_base64(encrypted_aes_key_b64_info['encrypted_aes_key'])
                    aes_key = crypto_utils.rsa_decrypt(receiver_rsa_private, encrypted_aes_key)
                    if aes_key:
                        debug_print(f"Received and decrypted AES key using RSA.")
                        print_info("AES key received (RSA).")
                    else:
                        print_info("Failed to decrypt AES key using RSA. Returning to key exchange selection.")
                        continue # Go back to key exchange selection
                else:
                    print_info("Error: Received RSA key exchange info without encrypted key. Returning to key exchange selection.")
                    continue # Go back to key exchange selection
            elif key_exchange_method == 'ecc':
                sender_ecc_public = key_exchange.import_ecc_public_key(sender_ecc_public_pem)
                shared_secret = key_exchange.perform_ecc_key_exchange(receiver_ecc_private, sender_ecc_public)
                aes_key = crypto_utils.generate_aes_key(shared_secret)
                debug_print(f"Generated AES key using ECC. Shared secret: {shared_secret.hex()}")
                print_info("AES key generated (ECC).")
            elif key_exchange_method == 'none':
                aes_key = crypto_utils.generate_simple_key()
                debug_print(f"Using simple (insecure) AES key: {aes_key.hex()}")
                print_info("Simple key in use.")
            elif key_exchange_method == 'dh':
                print_info("Initiating DH key exchange...") # Added log
                print_info("Waiting for Sender's DH public key...") # Added log
                sender_dh_public_info = network_utils.receive_json_data(conn)
                if not sender_dh_public_info: # Check for disconnection after key exchange method
                    print_info("Connection closed by sender during DH public key reception.")
                    conn.close() # 在這裡關閉連接
                    return False
                # --- 處理關閉信號 (如果 sender 在 DH 公鑰傳輸中發送) ---
                if sender_dh_public_info == SHUTDOWN_SIGNAL:
                    print_info("Received shutdown signal from sender during DH public key reception. Terminating receiver.")
                    conn.close()
                    return False
                # --- 結束處理 ---
                if sender_dh_public_info and 'dh_public_key' in sender_dh_public_info:
                    sender_dh_public = sender_dh_public_info['dh_public_key']
                    debug_print(f"Received DH public key: {sender_dh_public}")
                    receiver_dh_private = key_exchange.generate_dh_private_key()
                    receiver_dh_public = key_exchange.generate_dh_public_key(receiver_dh_private)
                    network_utils.send_json_data(conn, {'dh_public_key': receiver_dh_public})
                    print_info(f"Sent DH public key: {receiver_dh_public}") # Added log
                    shared_secret = key_exchange.compute_dh_shared_secret(receiver_dh_private, sender_dh_public)
                    aes_key = crypto_utils.generate_aes_key(long_to_bytes(shared_secret))
                    debug_print(f"Computed DH shared secret, AES key: {aes_key.hex()}")
                    print_info("AES key generated (DH).")
                else:
                    print_info("Error: Received DH key exchange info without public key. Returning to key exchange selection.")
                    continue # Go back to key exchange selection
            elif key_exchange_method == 'ecdh':
                sender_ecc_public = key_exchange.import_ecc_public_key(sender_ecc_public_pem)
                shared_secret = key_exchange.perform_ecc_key_exchange(receiver_ecc_private, sender_ecc_public)
                aes_key = crypto_utils.generate_aes_key(shared_secret)
                debug_print(f"Generated AES key using ECDH. Shared secret: {shared_secret.hex()}")
                print_info("AES key generated (ECDH).")
            else:
                print_info(f"Unknown key exchange method: {key_exchange_method}. Returning to key exchange selection.")
                continue # Go back to key exchange selection

            if aes_key is None:
                print_info("AES key was not established. Waiting for sender to re-establish key.")
                continue # Go back to key exchange selection

            while True: # Loop for receiving messages
                print_info("Waiting for encrypted message...") # Added log
                encrypted_data = network_utils.receive_json_data(conn)
                if not encrypted_data:
                    print_info("Connection closed by sender.")
                    conn.close() # 在這裡關閉連接
                    return False # Signal run_receiver to stop listening and exit
                
                # --- 處理會話重置信號 ---
                if encrypted_data == RESTART_SESSION_SIGNAL:
                    print_info("Received session restart signal from sender. Returning to key exchange setup.")
                    conn.close() # 關閉當前連接，因為 sender 會重新連接
                    return True # Signal run_receiver to accept a new connection
                # --- 處理關閉信號 ---
                if encrypted_data == SHUTDOWN_SIGNAL:
                    print_info("Received shutdown signal from sender. Terminating receiver.")
                    conn.close()
                    return False # Signal run_receiver to stop listening and exit
                # --- 結束新增 ---

                # 如果接收到的資料是金鑰交換相關的訊息，則跳出訊息迴圈
                if 'key_exchange' in encrypted_data or 'dh_public_key' in encrypted_data or 'encrypted_aes_key' in encrypted_data:
                    print_info("Received key exchange related message while in message loop. Returning to key exchange setup.")
                    conn.close() # 關閉當前連接，因為 sender 會重新連接
                    return True # Signal run_receiver to accept a new connection

                mode = encrypted_data.get('mode')
                iv_hex = encrypted_data.get('iv')
                nonce_hex = encrypted_data.get('nonce')
                ciphertext_hex = encrypted_data.get('ciphertext')
                tag_hex = encrypted_data.get('tag')
                associated_data_str = encrypted_data.get('associated_data', '')
                associated_data = associated_data_str.encode('utf-8')

                if mode and ciphertext_hex: # 只有當 mode 和 ciphertext_hex 都存在時才進行解密和打印 debug 訊息
                    debug_print(f"Decrypting with AES key: {aes_key.hex() if aes_key else 'None'}")
                    debug_print(f"Decrypting mode: {mode}")
                    debug_print(f"Decrypting iv_hex: {iv_hex}")
                    debug_print(f"Decrypting nonce_hex: {nonce_hex}")
                    debug_print(f"Decrypting ciphertext_hex: {ciphertext_hex[:50]}...")
                    debug_print(f"Decrypting tag_hex: {tag_hex}")
                    debug_print(f"Decrypting associated_data: {associated_data.decode('utf-8')}")

                    plaintext = crypto_utils.decrypt_aes(mode, aes_key, ciphertext_hex, iv_hex, nonce_hex, tag_hex, associated_data)
                    if plaintext:
                        print_info(f"Received and decrypted message from {sender_id}: {plaintext}")
                    else:
                        print_info("Failed to decrypt message.")
                else:
                    print_info("Received incomplete encrypted data.")
            
            # If inner loop broke due to 'p' or key exchange message, the outer loop continues
            # to wait for new key exchange info.
            # If inner loop broke because sender disconnected or shutdown signal, it would have returned False already.
            # So, if we reach here, it's either 'p' or a key exchange message, which means we need to re-evaluate
            # the key exchange info received.
            pass # Do nothing, let the outer loop continue

    else:
        print_info("Failed to receive initial info from sender.")
    conn.close() # 在這裡關閉連接
    return False # Normal exit if initial info failed or outer loop completes without restart signal

def run_receiver(host='127.0.0.1', port=12345):
    """啟動 receiver 並監聽連線。"""
    print_info("Starting receiver...")
    s = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            s = sock
            s.bind((host, port))
            s.listen()
            print_info(f"Listening on {host}:{port}")
            while True: # 這個外層迴圈是關鍵，用於持續接受新連接
                conn, addr = s.accept()
                with conn:
                    # handle_client 返回 True 表示需要重啟會話（即接受新連接），False 表示終止
                    should_restart_session = handle_client(conn, addr)
                    if not should_restart_session: # 如果 handle_client 返回 False，表示程式應該終止
                        break # 退出 run_receiver 的主迴圈
                    # 如果 should_restart_session 是 True，迴圈將繼續，接受下一個連接
    except Exception as e:
        print_info(f"An error occurred in run_receiver: {e}")
        traceback.print_exc()
    finally:
        if s:
            s.close()
            print_info("Socket closed.")
        print_info("Closing.")

if __name__ == "__main__":
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    run_receiver()
