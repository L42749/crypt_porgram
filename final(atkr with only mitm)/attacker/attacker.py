# attacker/attacker.py
import socket
import sys
import traceback
import json
import base64
import os
import time # 導入 time 模組
from Crypto.Util.number import long_to_bytes # 導入 long_to_bytes
from secure_comms import crypto_utils, key_exchange, network_utils

ATTACKER_DEBUG_MODE = True # Attacker will always be in debug mode for MITM scenario
RECEIVER_HOST = '127.0.0.1' # The real receiver's host
RECEIVER_PORT = 12345 # The real receiver's port
ATTACKER_LISTEN_HOST = '127.0.0.1' # Attacker listens on this host
ATTACKER_LISTEN_PORT = 12347 # Attacker listens on this port (where sender connects)

RESTART_SESSION_SIGNAL = {'control': 'restart_session'}
SHUTDOWN_SIGNAL = {'control': 'shutdown'}

def attacker_debug_print(message):
    global ATTACKER_DEBUG_MODE
    if ATTACKER_DEBUG_MODE:
        timestamp = crypto_utils.get_timestamp()
        print(f"[{timestamp}] [ATTACKER DEBUG] {message}")

def attacker_print_info(message):
    timestamp = crypto_utils.get_timestamp()
    print(f"[{timestamp}] [ATTACKER] {message}")

def mitm_main_loop(sender_conn, receiver_conn, attacker_mode):
    """
    處理 MITM 的主迴圈，包括金鑰交換和訊息轉發。
    此函數將在一個獨立的線程或進程中運行，用於處理一個完整的 MITM 會話。
    attacker_mode: 'active_mitm' (主動攻擊，可修改) 或 'listen_only' (被動監聽)
    """
    attacker_print_info(f"MITM session started in {attacker_mode.replace('_', ' ').title()} mode. Handling initial handshakes...")

    # --- Step 1: Attacker (Mallory) receives Sender's (Alice's) initial info ---
    sender_initial_info = network_utils.receive_json_data(sender_conn)
    if not sender_initial_info:
        attacker_print_info("Sender disconnected during initial handshake.")
        return False
    
    # Check for early shutdown from sender (Ctrl+C before full handshake)
    if sender_initial_info == SHUTDOWN_SIGNAL:
        attacker_print_info("Received shutdown signal from Sender during initial handshake. Terminating MITM session.")
        network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL) # Forward shutdown to receiver
        return False

    sender_ecc_public_pem_orig = sender_initial_info.get("ecc_public_key")
    sender_rsa_public_pem_orig = sender_initial_info.get("rsa_public_key")
    sender_id = sender_initial_info.get("identity", "unknown")
    sender_debug_mode = sender_initial_info.get("debug_mode", False)
    attacker_debug_print(f"Received initial info from Sender ({sender_id}). Sender Debug Mode: {'ON' if sender_debug_mode else 'OFF'}")
    network_utils.set_debug_mode(sender_debug_mode) # Attacker debug mode follows sender's debug mode

    # Attacker's keys to impersonate Receiver to Sender (Alice thinks she's talking to Bob)
    mallory_to_alice_ecc_private, mallory_to_alice_ecc_public = key_exchange.generate_ecc_keys()
    mallory_to_alice_rsa_private, mallory_to_alice_rsa_public = key_exchange.generate_rsa_keys()
    mallory_to_alice_ecc_public_pem = key_exchange.export_ecc_public_key(mallory_to_alice_ecc_public)
    mallory_to_alice_rsa_public_pem = key_exchange.export_rsa_public_key(mallory_to_alice_rsa_public)

    # --- Step 2: Attacker (Mallory) sends "Receiver's" public keys to Sender (Alice) ---
    # These are actually Mallory's keys
    response_to_sender = {
        "ecc_public_key": mallory_to_alice_ecc_public_pem,
        "rsa_public_key": mallory_to_alice_rsa_public_pem,
        "identity": "receiver_bob_impersonated_by_mallory", # Alice thinks this is Bob
        "debug_mode": ATTACKER_DEBUG_MODE
    }
    network_utils.send_json_data(sender_conn, response_to_sender)
    attacker_print_info(f"Sent Attacker's public keys (as Receiver) to Sender ({sender_id}).")


    # --- Step 3: Attacker (Mallory) sends "Sender's" initial info to Receiver (Bob) ---
    # These are actually Mallory's keys (or Alice's keys, for simplicity, let's use Mallory's new keys to impersonate Alice)
    mallory_to_bob_ecc_private, mallory_to_bob_ecc_public = key_exchange.generate_ecc_keys()
    mallory_to_bob_rsa_private, mallory_to_bob_rsa_public = key_exchange.generate_rsa_keys()
    mallory_to_bob_ecc_public_pem = key_exchange.export_ecc_public_key(mallory_to_bob_ecc_public)
    mallory_to_bob_rsa_public_pem = key_exchange.export_rsa_public_key(mallory_to_bob_rsa_public)

    initial_data_to_receiver = {
        "ecc_public_key": mallory_to_bob_ecc_public_pem, # Mallory's key impersonating Alice
        "rsa_public_key": mallory_to_bob_rsa_public_pem, # Mallory's key impersonating Alice
        "identity": sender_id, # Bob thinks this is Alice
        "debug_mode": ATTACKER_DEBUG_MODE # Let Bob know attacker's debug mode
    }
    network_utils.send_json_data(receiver_conn, initial_data_to_receiver)
    attacker_print_info(f"Sent Attacker's public keys (as Sender) to Receiver.")


    # --- Step 4: Attacker (Mallory) receives Receiver's (Bob's) public keys ---
    receiver_info = network_utils.receive_json_data(receiver_conn)
    if not receiver_info:
        attacker_print_info("Receiver disconnected during initial handshake (after receiving initial data).")
        return False
    
    # Check for shutdown from receiver
    if receiver_info == SHUTDOWN_SIGNAL:
        attacker_print_info("Received shutdown signal from Receiver during initial handshake. Terminating MITM session.")
        return False

    receiver_ecc_public_pem_orig = receiver_info.get("ecc_public_key")
    receiver_rsa_public_pem_orig = receiver_info.get("rsa_public_key")
    receiver_id = receiver_info.get("identity", "receiver_bob")
    attacker_print_info(f"Received Receiver's ({receiver_id}) public keys.")

    aes_key_sender_to_attacker = None # Key between Sender and Attacker
    aes_key_attacker_to_receiver = None # Key between Attacker and Receiver

    while True: # Main loop for key exchange and message forwarding
        # --- Key Exchange Phase (Sender-Attacker) ---
        key_exchange_info_from_sender = network_utils.receive_json_data(sender_conn)
        if not key_exchange_info_from_sender:
            attacker_print_info("Sender disconnected during key exchange setup. Terminating MITM session.")
            network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL) # Signal receiver to terminate
            break

        # --- Handle Restart/Shutdown Signals from Sender ---
        if key_exchange_info_from_sender == RESTART_SESSION_SIGNAL:
            attacker_print_info("Received session restart signal from Sender. Signaling Receiver to restart.")
            network_utils.send_json_data(receiver_conn, RESTART_SESSION_SIGNAL)
            # Reset AES keys for new session
            aes_key_sender_to_attacker = None
            aes_key_attacker_to_receiver = None
            # Continue to next iteration to handle Sender's new key exchange request
            continue # This will go back to the top of the 'while True' loop for key exchange info

        if key_exchange_info_from_sender == SHUTDOWN_SIGNAL:
            attacker_print_info("Received shutdown signal from Sender. Terminating MITM session.")
            network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL) # Forward shutdown to receiver
            break

        key_exchange_method = key_exchange_info_from_sender.get('key_exchange')
        if not key_exchange_method:
            attacker_print_info("Invalid key exchange info received from Sender. Skipping.")
            continue # Wait for valid info

        attacker_print_info(f"Observed key exchange method from Sender: {key_exchange_method}")

        # Forward key exchange method to Receiver (Mallory pretends Alice chose this method)
        network_utils.send_json_data(receiver_conn, {'key_exchange': key_exchange_method})

        # --- Perform Key Exchange between Sender and Attacker (Mallory impersonates Bob) ---
        # And between Attacker and Receiver (Mallory impersonates Alice)
        
        if key_exchange_method == 'rsa':
            # Sender encrypts AES key with Mallory_to_alice_rsa_public (Mallory's public key pretending to be Bob)
            encrypted_aes_key_from_sender_info = network_utils.receive_json_data(sender_conn)
            if not encrypted_aes_key_from_sender_info:
                attacker_print_info("Sender disconnected during RSA encrypted key reception.")
                network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL)
                break
            if encrypted_aes_key_from_sender_info == SHUTDOWN_SIGNAL: # Check if sender sent shutdown
                attacker_print_info("Received shutdown signal from Sender during RSA key reception. Terminating MITM session.")
                network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL)
                break

            encrypted_aes_key_from_sender = network_utils.decode_base64(encrypted_aes_key_from_sender_info['encrypted_aes_key'])
            # Mallory decrypts Alice's AES key using Mallory_to_alice_rsa_private
            aes_key_sender_to_attacker = crypto_utils.rsa_decrypt(mallory_to_alice_rsa_private, encrypted_aes_key_from_sender)
            if aes_key_sender_to_attacker: # Add None check
                attacker_print_info(f"Mallory decrypted AES key from Sender: {aes_key_sender_to_attacker.hex()}")
            else:
                attacker_print_info("Failed to decrypt AES key from Sender.")
                continue # Go back to key exchange selection

            # Mallory generates a new AES key for the Attacker-Receiver leg
            aes_key_attacker_to_receiver = os.urandom(32)
            # Mallory encrypts this new key with Receiver's (Bob's) original RSA public key
            encrypted_aes_key_to_receiver = crypto_utils.rsa_encrypt(key_exchange.import_rsa_public_key(receiver_rsa_public_pem_orig), aes_key_attacker_to_receiver)
            network_utils.send_json_data(receiver_conn, {'encrypted_aes_key': network_utils.encode_base64(encrypted_aes_key_to_receiver)})
            attacker_print_info(f"Mallory encrypted and sent new AES key to Receiver: {aes_key_attacker_to_receiver.hex()}")

        elif key_exchange_method == 'dh':
            # Sender sends DH public key to Mallory (pretending to be Bob)
            sender_dh_public_info = network_utils.receive_json_data(sender_conn)
            if not sender_dh_public_info:
                attacker_print_info("Sender disconnected during DH public key reception.")
                network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL)
                break
            if sender_dh_public_info == SHUTDOWN_SIGNAL:
                attacker_print_info("Received shutdown signal from Sender during DH public key reception. Terminating MITM session.")
                network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL)
                break

            sender_dh_public = sender_dh_public_info['dh_public_key']
            # Mallory generates DH private key for Sender-Attacker leg
            mallory_to_alice_dh_private = key_exchange.generate_dh_private_key()
            mallory_to_alice_dh_public = key_exchange.generate_dh_public_key(mallory_to_alice_dh_private)
            shared_secret_sa = key_exchange.compute_dh_shared_secret(mallory_to_alice_dh_private, sender_dh_public)
            aes_key_sender_to_attacker = crypto_utils.generate_aes_key(
                long_to_bytes(shared_secret_sa) # Use long_to_bytes here
            )
            if aes_key_sender_to_attacker: # Add None check
                attacker_print_info(f"Mallory computed DH shared secret with Sender. AES key: {aes_key_sender_to_attacker.hex()}")
            else:
                attacker_print_info("Failed to compute DH shared secret with Sender.")
                continue # Go back to key exchange selection

            # --- FIX: Mallory sends its DH public key (impersonating Receiver) back to Sender ---
            network_utils.send_json_data(sender_conn, {'dh_public_key': mallory_to_alice_dh_public})
            attacker_print_info(f"Mallory sent DH public key to Sender (as Receiver): {mallory_to_alice_dh_public}")

            # Mallory sends DH public key to Receiver (pretending to be Alice)
            # Mallory generates another DH private key for Attacker-Receiver leg
            mallory_to_bob_dh_private = key_exchange.generate_dh_private_key()
            mallory_to_bob_dh_public = key_exchange.generate_dh_public_key(mallory_to_bob_dh_private)
            network_utils.send_json_data(receiver_conn, {'dh_public_key': mallory_to_bob_dh_public})
            attacker_print_info(f"Mallory sent DH public key to Receiver: {mallory_to_bob_dh_public}")

            # Mallory receives DH public key from Receiver (Bob)
            receiver_dh_public_info = network_utils.receive_json_data(receiver_conn)
            if not receiver_dh_public_info:
                attacker_print_info("Receiver disconnected during DH public key reception.")
                break
            if receiver_dh_public_info == SHUTDOWN_SIGNAL:
                attacker_print_info("Received shutdown signal from Receiver during DH public key reception. Terminating MITM session.")
                break

            receiver_dh_public = receiver_dh_public_info['dh_public_key']
            shared_secret_ar = key_exchange.compute_dh_shared_secret(mallory_to_bob_dh_private, receiver_dh_public)
            aes_key_attacker_to_receiver = crypto_utils.generate_aes_key(
                long_to_bytes(shared_secret_ar) # Use long_to_bytes here
            )
            if aes_key_attacker_to_receiver: # Add None check
                attacker_print_info(f"Mallory computed DH shared secret with Receiver. AES key: {aes_key_attacker_to_receiver.hex()}")
            else:
                attacker_print_info("Failed to compute DH shared secret with Receiver.")
                continue # Go back to key exchange selection


        elif key_exchange_method == 'ecc' or key_exchange_method == 'ecdh':
            # This logic is similar for ECC and ECDH as they both involve shared secret derivation from ECC keys
            # Sender's initial ECC public key is already known (sender_ecc_public_pem_orig)
            
            # Mallory performs ECC key exchange with Sender
            # using Mallory_to_alice_ecc_private (Mallory's key impersonating Bob)
            sender_ecc_public_orig = key_exchange.import_ecc_public_key(sender_ecc_public_pem_orig)
            shared_secret_sa = key_exchange.perform_ecc_key_exchange(mallory_to_alice_ecc_private, sender_ecc_public_orig)
            aes_key_sender_to_attacker = crypto_utils.generate_aes_key(shared_secret_sa)
            if aes_key_sender_to_attacker: # Add None check
                attacker_print_info(f"Mallory established AES key with Sender ({key_exchange_method}): {aes_key_sender_to_attacker.hex()}")
            else:
                attacker_print_info(f"Failed to establish AES key with Sender ({key_exchange_method}).")
                continue # Go back to key exchange selection

            # Mallory performs ECC key exchange with Receiver
            # using Mallory_to_bob_ecc_private (Mallory's key impersonating Alice)
            receiver_ecc_public_orig = key_exchange.import_ecc_public_key(receiver_ecc_public_pem_orig)
            shared_secret_ar = key_exchange.perform_ecc_key_exchange(mallory_to_bob_ecc_private, receiver_ecc_public_orig)
            aes_key_attacker_to_receiver = crypto_utils.generate_aes_key(shared_secret_ar)
            if aes_key_attacker_to_receiver: # Add None check
                attacker_print_info(f"Mallory established AES key with Receiver ({key_exchange_method}): {aes_key_attacker_to_receiver.hex()}")
            else:
                attacker_print_info(f"Failed to establish AES key with Receiver ({key_exchange_method}).")
                continue # Go back to key exchange selection

        elif key_exchange_method == 'none':
            aes_key_sender_to_attacker = crypto_utils.generate_simple_key()
            aes_key_attacker_to_receiver = crypto_utils.generate_simple_key()
            attacker_print_info("Using simple (insecure) AES keys for both legs.")
        else:
            attacker_print_info(f"Unsupported key exchange method: {key_exchange_method}. Skipping to next loop.")
            continue # Go back to the beginning of the outer loop

        if aes_key_sender_to_attacker is None or aes_key_attacker_to_receiver is None:
            attacker_print_info("Failed to establish AES keys for both legs. Restarting key exchange.")
            continue # Go back to the beginning of the outer loop

        attacker_print_info("AES keys established for both legs. Starting message forwarding.")

        # --- Message Forwarding Loop ---
        while True:
            # --- From Sender to Receiver ---
            encrypted_data_from_sender = network_utils.receive_json_data(sender_conn)
            if not encrypted_data_from_sender:
                attacker_print_info("Sender disconnected during message forwarding. Terminating MITM session.")
                network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL)
                return False

            # --- Handle Restart/Shutdown Signals from Sender during message phase ---
            if encrypted_data_from_sender == RESTART_SESSION_SIGNAL:
                attacker_print_info("Received session restart signal from Sender during message phase. Signaling Receiver to restart.")
                network_utils.send_json_data(receiver_conn, RESTART_SESSION_SIGNAL)
                return True # Signal run_attacker to restart current MITM session

            if encrypted_data_from_sender == SHUTDOWN_SIGNAL:
                attacker_print_info("Received shutdown signal from Sender during message phase. Terminating MITM session.")
                network_utils.send_json_data(receiver_conn, SHUTDOWN_SIGNAL)
                return False # Signal run_attacker to terminate

            # Attempt to decrypt message from Sender
            mode_s = encrypted_data_from_sender.get('mode')
            iv_hex_s = encrypted_data_from_sender.get('iv')
            nonce_hex_s = encrypted_data_from_sender.get('nonce')
            ciphertext_hex_s = encrypted_data_from_sender.get('ciphertext')
            tag_hex_s = encrypted_data_from_sender.get('tag')
            associated_data_str_s = encrypted_data_from_sender.get('associated_data', '')
            associated_data_s = associated_data_str_s.encode('utf-8')

            plaintext = None
            if mode_s and ciphertext_hex_s:
                attacker_print_info(f"Intercepted message from Sender ({sender_id}). Attempting to decrypt...")
                plaintext = crypto_utils.decrypt_aes(
                    mode_s, aes_key_sender_to_attacker, ciphertext_hex_s, iv_hex_s, nonce_hex_s, tag_hex_s, associated_data_s
                )
                if plaintext:
                    attacker_print_info(f"Successfully decrypted: {plaintext}")
                    # --- MITM Modification Feature (always active in this version) ---
                    modify_input = input(f"[ATTACKER] Intercepted: '{plaintext}'. Modify message? (yes/no, default: no): ").lower()
                    if modify_input == 'yes' or modify_input == 'y':
                        new_message = input("[ATTACKER] Enter new message: ")
                        plaintext = new_message
                        attacker_print_info(f"Message modified to: '{plaintext}'")
                    # --- End MITM Modification Feature ---

                    # Re-encrypt for Receiver using aes_key_attacker_to_receiver
                    # Unpack values from encrypt_aes more explicitly to handle None correctly
                    ciphertext_r, iv_or_nonce_r, tag_r = crypto_utils.encrypt_aes(
                        mode_s, aes_key_attacker_to_receiver, plaintext, associated_data_s
                    )
                    
                    if ciphertext_r:
                        # Initialize IV, Nonce, and Tag to None
                        iv_to_send = None
                        nonce_to_send = None
                        tag_to_send = None

                        # Conditionally assign based on mode_s and whether iv_or_nonce_r/tag_r is not None
                        if mode_s == 'CBC':
                            iv_to_send = iv_or_nonce_r.hex() if iv_or_nonce_r else None
                        elif mode_s == 'CTR':
                            nonce_to_send = iv_or_nonce_r.hex() if iv_or_nonce_r else None
                        elif mode_s == 'GCM':
                            nonce_to_send = iv_or_nonce_r.hex() if iv_or_nonce_r else None
                            tag_to_send = tag_r.hex() if tag_r else None # Ensure tag_r is not None before .hex()
                        # For ECB, iv_to_send, nonce_to_send, tag_to_send remain None as initialized

                        encrypted_data_to_receiver = {
                            'mode': mode_s,
                            'iv': iv_to_send,
                            'nonce': nonce_to_send,
                            'tag': tag_to_send,
                            'ciphertext': ciphertext_r.hex(),
                            'associated_data': associated_data_s.decode('utf-8')
                        }
                        network_utils.send_json_data(receiver_conn, encrypted_data_to_receiver)
                        attacker_print_info(f"Forwarded (possibly modified) encrypted message to Receiver ({receiver_id}).")
                    else:
                        attacker_print_info("Failed to re-encrypt message for Receiver.")
                else:
                    attacker_print_info("Failed to decrypt message from Sender.")
            else:
                attacker_print_info("Received incomplete or unrecognized data from Sender for decryption attempt.")
            
            # Note: For full duplex, you'd also need a separate thread to handle messages from Receiver to Sender
            # For simplicity in this example, we'll assume Sender initiates most communication.
            # If Receiver sends replies, they won't be intercepted by this single-threaded loop.
            # To add Receiver-to-Sender MITM, this whole function needs to be a multi-threaded proxy.
            # For this demonstration, we focus on Sender-to-Receiver modification.

    return False # If we break out of the main loop, it's typically a termination

def run_attacker(attacker_listen_host=ATTACKER_LISTEN_HOST, attacker_listen_port=ATTACKER_LISTEN_PORT):
    """啟動 attacker 並監聽 sender 連接。"""
    attacker_print_info("Starting Attacker (MITM Proxy)...")
    listening_socket = None
    try:
        listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listening_socket.bind((attacker_listen_host, attacker_listen_port))
        listening_socket.listen(1) # Only accept one Sender connection at a time for simplicity
        attacker_print_info(f"Listening for Sender connections on {attacker_listen_host}:{attacker_listen_port}")

        while True: # Outer loop to continuously accept new MITM sessions
            sender_conn = None
            receiver_conn = None
            try:
                # 硬編碼為 'active_mitm'，移除模式選擇提示
                current_attacker_mode = 'active_mitm'
                attacker_print_info("Attacker mode set to: MITM (Active) by default.")
                
                # Accept connection from Sender
                sender_conn, sender_addr = listening_socket.accept()
                attacker_print_info(f"Accepted connection from Sender: {sender_addr}")

                # Establish connection to Receiver
                receiver_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                receiver_conn.connect((RECEIVER_HOST, RECEIVER_PORT))
                attacker_print_info(f"Established connection to Receiver at {RECEIVER_HOST}:{RECEIVER_PORT}")

                # Handle the full MITM session, passing the chosen mode
                should_continue_listening = mitm_main_loop(sender_conn, receiver_conn, current_attacker_mode)
                
                if not should_continue_listening:
                    attacker_print_info("MITM session ended. Stopping attacker.")
                    break # Terminate Attacker if mitm_main_loop indicates so

            except ConnectionRefusedError:
                attacker_print_info(f"Could not connect to Receiver at {RECEIVER_HOST}:{RECEIVER_PORT}. Make sure Receiver is running.")
                time.sleep(2) # Wait before retrying to accept Sender connections
                continue # Go back to accepting Sender connections
            except Exception as e:
                attacker_print_info(f"An error occurred in Attacker main loop: {e}")
                traceback.print_exc()
                # Decide whether to break or continue accepting new connections based on error severity
                # For now, let's break on any unhandled error to prevent infinite loops
                break 
            finally:
                if sender_conn:
                    sender_conn.close()
                    attacker_print_info("Sender connection closed by Attacker.")
                if receiver_conn:
                    receiver_conn.close()
                    attacker_print_info("Receiver connection closed by Attacker.")
        
    except KeyboardInterrupt:
        attacker_print_info("\nAttacker detected Ctrl+C. Shutting down.")
    except Exception as e:
        attacker_print_info(f"An error occurred during Attacker startup: {e}")
        traceback.print_exc()
    finally:
        if listening_socket:
            listening_socket.close()
            attacker_print_info("Attacker listening socket closed.")
        attacker_print_info("Attacker stopped.")

if __name__ == "__main__":
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    network_utils.set_debug_mode(ATTACKER_DEBUG_MODE) # Set network_utils's debug mode
    run_attacker()
