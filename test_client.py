#!/usr/bin/env python3
import socket
import struct
import os
import sys

def create_stun_binding_request():
    """Create a STUN Binding Request message"""
    # Message Type: Binding Request (0x0001)
    message_type = 0x0001
    
    # Message Length: 0 (no attributes)
    message_length = 0
    
    # Magic Cookie
    magic_cookie = 0x2112A442
    
    # Transaction ID (96 bits / 12 bytes)
    transaction_id = os.urandom(12)
    
    # Pack the header
    header = struct.pack('>HHI', message_type, message_length, magic_cookie)
    
    return header + transaction_id, transaction_id

def parse_stun_response(data, expected_transaction_id):
    """Parse a STUN response message"""
    if len(data) < 20:
        print("Response too short")
        return
    
    # Parse header
    message_type, message_length, magic_cookie = struct.unpack('>HHI', data[0:8])
    transaction_id = data[8:20]
    
    print(f"Response Type: 0x{message_type:04x}")
    print(f"Message Length: {message_length}")
    print(f"Magic Cookie: 0x{magic_cookie:08x}")
    
    if transaction_id != expected_transaction_id:
        print("Transaction ID mismatch!")
        return
    
    print("Transaction ID matches")
    
    # Parse attributes
    offset = 20
    while offset < 20 + message_length:
        if offset + 4 > len(data):
            break
            
        attr_type, attr_length = struct.unpack('>HH', data[offset:offset+4])
        attr_value = data[offset+4:offset+4+attr_length]
        
        print(f"\nAttribute Type: 0x{attr_type:04x}")
        print(f"Attribute Length: {attr_length}")
        
        if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
            family = attr_value[1]
            xor_port = struct.unpack('>H', attr_value[2:4])[0]
            
            # Decode port
            port = xor_port ^ (magic_cookie >> 16)
            
            if family == 0x01:  # IPv4
                xor_ip = attr_value[4:8]
                magic_bytes = struct.pack('>I', magic_cookie)
                ip_bytes = bytes(a ^ b for a, b in zip(xor_ip, magic_bytes))
                ip = '.'.join(str(b) for b in ip_bytes)
                
                print(f"XOR-MAPPED-ADDRESS: {ip}:{port}")
        
        # Move to next attribute (with padding)
        offset += 4 + attr_length
        padding = (4 - (attr_length % 4)) % 4
        offset += padding

def main():
    if len(sys.argv) > 1:
        server_addr = sys.argv[1]
        if ':' in server_addr:
            host, port = server_addr.split(':')
            port = int(port)
        else:
            host = server_addr
            port = 3478
    else:
        host = 'localhost'
        port = 3478
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    
    # Create STUN request
    request, transaction_id = create_stun_binding_request()
    
    print(f"Sending STUN Binding Request to {host}:{port}")
    print(f"Request size: {len(request)} bytes")
    
    try:
        # Send request
        sock.sendto(request, (host, port))
        
        # Receive response
        data, addr = sock.recvfrom(1024)
        print(f"\nReceived {len(data)} bytes from {addr}")
        
        # Parse response
        parse_stun_response(data, transaction_id)
        
    except socket.timeout:
        print("Request timed out")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()