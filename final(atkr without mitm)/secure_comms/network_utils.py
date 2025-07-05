# secure_comms/network_utils.py
import socket
import json
import base64
from secure_comms import crypto_utils # Import crypto_utils to use get_timestamp

DEBUG_MODE_GLOBAL = False # This global variable will be set by sender/receiver

def set_debug_mode(debug):
    """設定網路工具模組的除錯模式。"""
    global DEBUG_MODE_GLOBAL
    DEBUG_MODE_GLOBAL = debug

def debug_print_network(message):
    """在除錯模式開啟時，印出網路相關的除錯訊息。"""
    global DEBUG_MODE_GLOBAL
    if DEBUG_MODE_GLOBAL:
        timestamp = crypto_utils.get_timestamp()
        print(f"[{timestamp}] [NETWORK DEBUG] {message}") # Changed tag for clarity

def send_json_data(conn, data):
    """將 JSON 資料透過 socket 傳送。"""
    try:
        json_str = json.dumps(data)
        data_to_send = json_str.encode('utf-8') + b'\n' # Added newline delimiter
        conn.sendall(data_to_send)
        debug_print_network(f"Sent JSON: {json_str[:100]}... (Length: {len(data_to_send)} bytes)") # Log length
    except Exception as e:
        timestamp = crypto_utils.get_timestamp()
        print(f"[{timestamp}] [NETWORK ERROR] Error sending JSON: {e}")

# Global buffer for persistent connection parsing
_receive_buffer = {} # Stores buffer per connection (socket object as key)

def receive_json_data(conn):
    """從 socket 接收 JSON 資料。"""
    # Initialize buffer for this connection if it doesn't exist
    if conn not in _receive_buffer:
        _receive_buffer[conn] = b''

    buffer = _receive_buffer[conn]
    
    try:
        debug_print_network("Receiving JSON...")
        while True:
            # Try to find a complete message in the current buffer first
            if b'\n' in buffer:
                line, rest = buffer.split(b'\n', 1)
                debug_print_network(f"Found newline in buffer. Line: {line[:100]}..., Rest: {rest[:100]}...")
                try:
                    received_data = json.loads(line.decode('utf-8'))
                    debug_print_network(f"Successfully parsed JSON: {json.dumps(received_data)[:100]}...")
                    _receive_buffer[conn] = rest # Update global buffer for next read
                    return received_data # Return valid JSON
                except json.JSONDecodeError as e:
                    timestamp = crypto_utils.get_timestamp()
                    print(f"[{timestamp}] [NETWORK ERROR] JSON Decode Error: {e}, Corrupted data: {line.decode('utf-8', errors='ignore')}")
                    # Discard corrupted line and continue trying to read from the rest of the buffer
                    buffer = rest
                    _receive_buffer[conn] = rest # Update global buffer
                    continue # Try to parse the next line in the buffer
            
            # If no complete message in buffer, receive more data
            chunk = conn.recv(4096)
            debug_print_network(f"Received chunk: {chunk[:50]}... (Length: {len(chunk)} bytes)")
            if not chunk:
                debug_print_network("Received empty chunk, connection likely closed.")
                # Clean up buffer for this connection if it's closing
                if conn in _receive_buffer:
                    del _receive_buffer[conn]
                return None # Connection closed
            
            buffer += chunk
            debug_print_network(f"Appended chunk. Current buffer: {buffer[:100]}... (Length: {len(buffer)} bytes)")

    except Exception as e:
        timestamp = crypto_utils.get_timestamp()
        print(f"[{timestamp}] [NETWORK ERROR] Error receiving JSON: {e}")
        # Clean up buffer for this connection on error
        if conn in _receive_buffer:
            del _receive_buffer[conn]
        return None

def encode_base64(data):
    """將位元組資料編碼為 Base64 字串。"""
    return base64.b64encode(data).decode('utf-8')

def decode_base64(s):
    """將 Base64 字串解碼為位元組資料。"""
    return base64.b64decode(s.encode('utf-8'))
