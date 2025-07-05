# sender/sender.py
import socket
import sys
import traceback
from secure_comms import crypto_utils, key_exchange, network_utils
from Crypto.Util.number import long_to_bytes
import os # Import os for os.urandom
import time # 導入 time 模組

DEBUG_MODE = False
ATTACKER_HOST = '127.0.0.1'
ATTACKER_PORT = 12347 # Attacker will listen on this port
RESTART_SESSION_SIGNAL = {'control': 'restart_session'} # 會話重置信號
SHUTDOWN_SIGNAL = {'control': 'shutdown'} # 關閉信號

def debug_print(message):
    global DEBUG_MODE
    if DEBUG_MODE:
        timestamp = crypto_utils.get_timestamp()
        print(f"[{timestamp}] [DEBUG] Sender: {message}")

def print_info(message):
    timestamp = crypto_utils.get_timestamp()
    print(f"[{timestamp}] Sender: {message}")

def send_encrypted_message(mode, message, conn, aes_key, sender_id, attacker_conn=None):
    """使用 AES 加密訊息並透過 socket 傳送，同時轉發給 attacker。"""
    print_info(f"Sending message (AES encrypted): {message}")
    debug_print(f"AES key in send_encrypted_message: {aes_key.hex() if aes_key else None}")
    debug_print(f"AES mode = {mode}")
    associated_data = sender_id.encode('utf-8')
    ciphertext, iv, tag = crypto_utils.encrypt_aes(mode_str=mode.upper(), key=aes_key, plaintext=message, associated_data=associated_data)

    if ciphertext is None:
        print_info("AES encryption failed. Not sending message.")
        return

    encrypted_data = {
        'mode': mode.upper(),
        'iv': iv.hex() if mode.upper() != 'GCM' and iv else None,
        'nonce': iv.hex() if mode.upper() == 'GCM' and iv else (iv.hex() if mode.upper() == 'CTR' and iv else None), # CTR uses iv as nonce
        'tag': tag.hex() if mode.upper() == 'GCM' else None,
        'ciphertext': ciphertext.hex(),
        'associated_data': associated_data.decode('utf-8')
    }
    
    # --- GCM 偵錯訊息 ---
    if mode.upper() == 'GCM':
        debug_print(f"GCM parameters being sent:")
        debug_print(f"  Nonce (hex): {encrypted_data.get('nonce')}")
        debug_print(f"  Tag (hex): {encrypted_data.get('tag')}")
        debug_print(f"  Associated Data (decoded): {encrypted_data.get('associated_data')}")
    # --- 結束 GCM 偵錯訊息 ---

    debug_print(f"Sending encrypted data to Receiver: {encrypted_data}")
    network_utils.send_json_data(conn, encrypted_data)
    print_info(f"AES encrypted message sent to Receiver using {mode.upper()}.")

    if attacker_conn:
        try:
            debug_print(f"Sending encrypted data to Attacker: {encrypted_data}")
            network_utils.send_json_data(attacker_conn, encrypted_data)
            debug_print("Encrypted message forwarded to Attacker.")
        except Exception as e:
            print_info(f"Error forwarding message to Attacker: {e}")
            debug_print(f"Attacker connection might be closed or invalid: {e}")


def send_encrypted_aes_key(encrypted_key, conn, attacker_conn=None):
    """傳送 RSA 加密的 AES 金鑰，同時轉發給 attacker。"""
    key_data = {'encrypted_aes_key': network_utils.encode_base64(encrypted_key)}
    debug_print(f"Sending encrypted AES key data to Receiver: {key_data}")
    network_utils.send_json_data(conn, key_data)
    print_info("Sent encrypted AES key to Receiver.")

    if attacker_conn:
        try:
            debug_print(f"Sending encrypted AES key data to Attacker: {key_data}")
            network_utils.send_json_data(attacker_conn, key_data)
            debug_print("Encrypted AES key forwarded to Attacker.")
        except Exception as e:
            print_info(f"Error forwarding AES key to Attacker: {e}")
            debug_print(f"Attacker connection might be closed or invalid: {e}")


def handle_connection(conn, addr, sender_username, attacker_conn=None):
    """處理與 receiver 的連線，進行金鑰交換和訊息傳送。
       返回 True 表示需要重新啟動會話，False 表示正常結束。
    """
    global DEBUG_MODE
    print_info(f"Connected to {addr}")

    sender_id = sender_username # Use the provided username
    sender_ecc_private, sender_ecc_public = key_exchange.generate_ecc_keys()
    sender_rsa_private, sender_rsa_public = key_exchange.generate_rsa_keys()
    sender_ecc_public_pem = key_exchange.export_ecc_public_key(sender_ecc_public)
    sender_rsa_public_pem = key_exchange.export_rsa_public_key(sender_rsa_public)

    debug_print(f"Sender ECC Private Key: {sender_ecc_private.d if DEBUG_MODE else 'hidden'}")
    debug_print(f"Sender ECC Public Key (PEM): {sender_ecc_public_pem if DEBUG_MODE else 'hidden'}")
    debug_print(f"Sender RSA Private Key: {sender_rsa_private.exportKey().decode() if DEBUG_MODE else 'hidden'}")
    debug_print(f"Sender RSA Public Key (PEM): {sender_rsa_public_pem if DEBUG_MODE else 'hidden'}")

    initial_data = {
        "ecc_public_key": sender_ecc_public_pem,
        "rsa_public_key": sender_rsa_public_pem,
        "identity": sender_id,
        "debug_mode": DEBUG_MODE
    }
    network_utils.send_json_data(conn, initial_data)
    print_info("Sent ECC and RSA public keys and debug mode status.")

    # Forward initial data to attacker as well
    if attacker_conn:
        try:
            debug_print(f"Sending initial data to Attacker: {initial_data}")
            network_utils.send_json_data(attacker_conn, initial_data)
            debug_print("Initial data forwarded to Attacker.")
        except Exception as e:
            print_info(f"Error forwarding initial data to Attacker: {e}")
            debug_print(f"Attacker connection might be closed or invalid: {e}")

    receiver_info = network_utils.receive_json_data(conn)
    if receiver_info:
        receiver_ecc_public_pem = receiver_info.get("ecc_public_key")
        receiver_rsa_public_pem = receiver_info.get("rsa_public_key")
        print_info(f"Received receiver's public keys.") # Simplified for non-debug
        
        # Only print public keys if in debug mode
        debug_print(f"Received receiver's ECC public key: {receiver_ecc_public_pem[:50]}...")
        debug_print(f"Received receiver's RSA public key: {receiver_rsa_public_pem[:50]}...")
        
        receiver_ecc_public = key_exchange.import_ecc_public_key(receiver_ecc_public_pem)
        receiver_rsa_public = key_exchange.import_rsa_public_key(receiver_rsa_public_pem)

        debug_print(f"Receiver ECC Public Key (PEM): {receiver_ecc_public_pem if DEBUG_MODE else 'hidden'}")
        debug_print(f"Receiver RSA Public Key (PEM): {receiver_rsa_public_pem if DEBUG_MODE else 'hidden'}")

        # Forward receiver's info to attacker as well
        if attacker_conn:
            try:
                debug_print(f"Sending receiver info to Attacker: {receiver_info}")
                network_utils.send_json_data(attacker_conn, receiver_info)
                debug_print("Receiver info forwarded to Attacker.")
            except Exception as e:
                print_info(f"Error forwarding receiver info to Attacker: {e}")
                debug_print(f"Attacker connection might be closed or invalid: {e}")

        while True: # Outer loop for key exchange method
            aes_key = None
            key_exchange_method = None
            
            while True: # Loop for choosing key exchange method
                key_exchange_input = input("Choose key exchange/encryption (1: RSA, 2: ECC, 3: DH, 4: ECDH, 5: None, p: Previous menu): ")
                if key_exchange_input.lower() == 'p': # 處理 'p' 輸入
                    print_info("Requesting session restart.")
                    network_utils.send_json_data(conn, RESTART_SESSION_SIGNAL)
                    if attacker_conn:
                        network_utils.send_json_data(attacker_conn, RESTART_SESSION_SIGNAL)
                    # Add a small delay to allow receiver/attacker to process the signal and re-enter accept()
                    time.sleep(0.5) # <--- 新增延遲
                    return True # Signal run_sender to restart the entire connection
                
                if key_exchange_input == '1' or key_exchange_input.lower() == 'r' or key_exchange_input.lower() == 'rsa':
                    key_exchange_method = 'rsa'
                    break
                elif key_exchange_input == '2' or key_exchange_input.lower() == 'e' or key_exchange_input.lower() == 'ecc':
                    key_exchange_method = 'ecc'
                    break
                elif key_exchange_input == '3' or key_exchange_input.lower() == 'd' or key_exchange_input.lower() == 'dh':
                    key_exchange_method = 'dh'
                    break
                elif key_exchange_input == '4' or key_exchange_input.lower() == 'ecdh':
                    key_exchange_method = 'ecdh'
                    break
                elif key_exchange_input == '5' or key_exchange_input == '' or key_exchange_input.lower() == 'n' or key_exchange_input.lower() == 'none':
                    key_exchange_method = 'none'
                    break
                else:
                    print("Invalid input. Please enter 1 for RSA, 2 for ECC, 3 for DH, 4 for ECDH, 5 for None, or 'p' to restart.")

            # Perform key exchange based on selected method
            network_utils.send_json_data(conn, {'key_exchange': key_exchange_method}) # Send key exchange method to receiver

            if attacker_conn:
                try:
                    debug_print(f"Sending key exchange method to Attacker: {key_exchange_method}")
                    network_utils.send_json_data(attacker_conn, {'key_exchange': key_exchange_method})
                    debug_print("Key exchange method forwarded to Attacker.")
                except Exception as e:
                    print_info(f"Error forwarding key exchange method to Attacker: {e}")
                    debug_print(f"Attacker connection might be closed or invalid: {e}")

            if key_exchange_method == 'rsa':
                aes_key = os.urandom(32) # 生成一個隨機的 32 位元組 AES 金鑰
                encrypted_aes_key = crypto_utils.rsa_encrypt(receiver_rsa_public, aes_key)
                send_encrypted_aes_key(encrypted_aes_key, conn, attacker_conn) # Pass attacker_conn
                print_info("Generated and sent RSA-encrypted AES key.")
                debug_print(f"Generated AES key (RSA): {aes_key.hex()}")
            elif key_exchange_method == 'ecc':
                shared_secret = key_exchange.perform_ecc_key_exchange(sender_ecc_private, receiver_ecc_public)
                aes_key = crypto_utils.generate_aes_key(shared_secret)
                print_info("Generated AES key using ECC.")
                debug_print(f"Shared secret (ECC): {shared_secret.hex()}")
                debug_print(f"Generated AES key (ECC): {aes_key.hex()}")
            elif key_exchange_method == 'none':
                aes_key = crypto_utils.generate_simple_key() # 這裡維持硬編碼金鑰，因為這是 "none" 模式的特性
                print_info("Using simple (insecure) AES key.")
                debug_print(f"Simple AES key: {aes_key.hex()}")
            elif key_exchange_method == 'dh':
                print_info("Initiating DH key exchange...") # Added log
                print_info("Waiting for Sender's DH public key...") # Added log
                sender_dh_private = key_exchange.generate_dh_private_key()
                sender_dh_public = key_exchange.generate_dh_public_key(sender_dh_private)
                debug_print(f"Sender DH Private Key: {sender_dh_private}")
                debug_print(f"Sender DH Public Key: {sender_dh_public}")
                network_utils.send_json_data(conn, {'dh_public_key': sender_dh_public})
                print_info(f"Sent DH public key: {sender_dh_public}")

                if attacker_conn: # Forward DH public key to attacker
                    try:
                        debug_print(f"Sending DH public key to Attacker: {sender_dh_public}")
                        network_utils.send_json_data(attacker_conn, {'dh_public_key': sender_dh_public})
                        debug_print("DH public key forwarded to Attacker.")
                    except Exception as e:
                        print_info(f"Error forwarding DH public key to Attacker: {e}")

                print_info("Waiting for Receiver's DH public key...") # Added log
                receiver_dh_public_info = network_utils.receive_json_data(conn)
                if receiver_dh_public_info and 'dh_public_key' in receiver_dh_public_info:
                    receiver_dh_public = receiver_dh_public_info['dh_public_key']
                    debug_print(f"Receiver DH Public Key: {receiver_dh_public}")
                    # Forward receiver's DH public key to attacker
                    if attacker_conn:
                        try:
                            debug_print(f"Sending receiver's DH public key to Attacker: {receiver_dh_public}")
                            network_utils.send_json_data(attacker_conn, {'dh_public_key': receiver_dh_public})
                            debug_print("Receiver's DH public key forwarded to Attacker.")
                        except Exception as e:
                            print_info(f"Error forwarding receiver's DH public key to Attacker: {e}")

                    shared_secret_dh = key_exchange.compute_dh_shared_secret(sender_dh_private, receiver_dh_public)
                    aes_key = crypto_utils.generate_aes_key(long_to_bytes(shared_secret_dh))
                    print_info("Computed DH shared secret and AES key.")
                    debug_print(f"DH Shared Secret: {shared_secret_dh}")
                    debug_print(f"Generated AES key (DH): {aes_key.hex()}")
                else:
                    print_info("Error receiving DH public key from receiver. Returning to key exchange selection.")
                    continue # Go back to key exchange selection
            elif key_exchange_method == 'ecdh':
                shared_secret_ecdh = key_exchange.perform_ecc_key_exchange(sender_ecc_private, receiver_ecc_public)
                aes_key = crypto_utils.generate_aes_key(shared_secret_ecdh)
                print_info("Generated AES key using ECDH.")
                debug_print(f"Shared secret (ECDH): {shared_secret_ecdh.hex()}")
                debug_print(f"Generated AES key (ECDH): {aes_key.hex()}")
            else:
                print_info("No valid key exchange method selected. Returning to key exchange selection.")
                continue # Go back to key exchange selection

            if aes_key is None:
                print_info("AES key was not established. Please choose a valid key exchange method.")
                continue # Go back to key exchange selection

            while True: # Inner loop for AES mode and message sending
                mode_options = "Choose AES mode (1: ECB, 2: CBC"
                if key_exchange_method != 'none':
                    mode_options += ", 3: CTR"
                mode_options += ", 4: GCM, p: Previous menu): "
                
                # AES 模式預設為 GCM
                mode_input = input(mode_options).lower() or '4' # Default to '4' (GCM)
                
                if mode_input == 'p':
                    print_info("Requesting session restart.")
                    network_utils.send_json_data(conn, RESTART_SESSION_SIGNAL)
                    if attacker_conn:
                        network_utils.send_json_data(attacker_conn, RESTART_SESSION_SIGNAL)
                    time.sleep(0.5) # <--- 新增延遲
                    return True # Signal run_sender to restart the entire connection
                
                if mode_input == '1' or mode_input == 'ecb':
                    mode = 'ECB'
                elif mode_input == '2' or mode_input == 'cbc':
                    mode = 'CBC'
                elif (mode_input == '3' or mode_input == 'ctr') and key_exchange_method != 'none':
                    mode = 'CTR'
                elif mode_input == '4' or mode_input == 'gcm':
                    mode = 'GCM'
                else:
                    print("Invalid mode. Please choose a valid option or 'p'.")
                    continue # Continue inner loop for AES mode selection

                # If a valid mode is selected (not 'p')
                try: # Added try-except around message input and send
                    # 訊息輸入預設為 "hello from sender"
                    message = input("Enter message to send (default: hello from sender): ") or "hello from sender"
                    send_encrypted_message(mode, message, conn, aes_key, sender_id, attacker_conn) # Pass attacker_conn
                except Exception as e:
                    print_info(f"An error occurred while sending message: {e}")
                    debug_print(f"Traceback: {traceback.format_exc()}") # Print full traceback in debug
                    time.sleep(0.5) # <--- 新增延遲
                    return True # Signal run_sender to restart the entire connection
                # After sending, the loop continues, returning to AES mode selection

            # If the inner loop breaks (due to 'p' input or error), the outer loop continues
            # which will re-prompt for key exchange method.

    else:
        print_info("Failed to receive initial info from sender.")
    # 不關閉連接，讓外部的 run_sender 處理 Ctrl+C
    return False # Normal exit from handle_connection

def run_sender(host='127.0.0.1', port=12345):
    """啟動 sender 並連接到 receiver。"""
    global DEBUG_MODE

    # 在 debug mode 之前要可設定 username
    username_input = input("Enter your username (default: alice): ")
    sender_username = username_input if username_input else "alice"

    debug_mode_input = input("Enable debug mode? (yes/no, default: no): ").lower() or 'no'
    if debug_mode_input == 'yes' or debug_mode_input == 'y':
        DEBUG_MODE = True
        print_info("Debug mode is ON.")
    else:
        print_info("Debug mode is OFF.")

    network_utils.set_debug_mode(DEBUG_MODE) # 設定 network_utils 的 debug mode
    print_info("Starting sender...")
    
    while True: # Outer loop to allow full session restarts
        s = None
        attacker_s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            print_info(f"Connected to Receiver at {host}:{port}")

            # Connect to attacker
            try:
                attacker_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                attacker_s.connect((ATTACKER_HOST, ATTACKER_PORT))
                print_info(f"Connected to Attacker at {ATTACKER_HOST}:{ATTACKER_PORT}")
            except ConnectionRefusedError:
                print_info(f"Could not connect to Attacker at {ATTACKER_HOST}:{ATTACKER_PORT}. Continuing without forwarding to Attacker.")
                attacker_s = None
            except Exception as e:
                print_info(f"An unexpected error occurred connecting to Attacker: {e}. Continuing without forwarding to Attacker.")
                attacker_s = None

            # handle_connection now manages its own loops for session restarts.
            # It will return True if a restart is needed, False if shutdown/normal exit
            should_restart = handle_connection(s, (host, port), sender_username, attacker_s) 
            
            if not should_restart: # If handle_connection returns False (shutdown/normal exit), break the outer loop
                break
            
            # If should_restart is True, it means 'p' was pressed. Close old sockets and prepare for new ones.
            print_info("Restarting session (re-establishing connections)...")
            # Sockets are already closed by handle_connection before returning True.
            # The loop will continue and create new sockets in the next iteration.

        except ConnectionRefusedError:
            print_info("Connection to Receiver refused. Make sure the receiver is running.")
            import time
            time.sleep(2) # Wait a bit before retrying
            continue # Try connecting again
        except KeyboardInterrupt:
            print_info("\nSender detected Ctrl+C. Sending shutdown signal to Receiver and Attacker...")
            # Attempt to send shutdown signal to Receiver
            if s:
                try:
                    network_utils.send_json_data(s, SHUTDOWN_SIGNAL)
                    print_info("Shutdown signal sent to Receiver.")
                except Exception as e:
                    print_info(f"Error sending shutdown signal to Receiver: {e}")
            # Attempt to send shutdown signal to Attacker
            if attacker_s:
                try:
                    network_utils.send_json_data(attacker_s, SHUTDOWN_SIGNAL)
                    print_info("Shutdown signal sent to Attacker.")
                except Exception as e:
                    print_info(f"Error sending shutdown signal to Attacker: {e}")
            break # Break the outer loop on Ctrl+C
        except Exception as e:
            print_info(f"An error occurred in run_sender: {e}")
            traceback.print_exc()
            break # Exit on unhandled critical error
        finally:
            # Ensure sockets are closed if they were opened
            if s:
                s.close()
                print_info("Receiver socket closed.")
            if attacker_s:
                attacker_s.close()
                print_info("Attacker socket closed.")
        
        # If handle_connection returned True (restart), the loop will continue and create new sockets
        print_info("Restarting session...")

    print_info("Exiting sender.")

if __name__ == "__main__":
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    run_sender()
