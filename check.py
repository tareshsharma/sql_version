#!/usr/bin/env python3
import socket
import sys

prelogin_packet = bytes([
    0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
    0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03,
    0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
    0x55, 0x00, 0x00, 0x00, 0x4d, 0x53, 0x53, 0x51,
    0x4c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00
])

def get_sql_version(host, port=1433):
    try:
        print(f"[*] Checking {host}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # Increased to 10 seconds
        sock.connect((host, port))
        print(f"[+] Connected to {host}")
        
        sock.send(prelogin_packet)
        print(f"[+] Sent pre-login packet, waiting for response...")
        
        response = sock.recv(4096)  # Increased buffer size
        print(f"[+] Received {len(response)} bytes")
        sock.close()
        
        # Debug: Show raw response
        print(f"[DEBUG] Raw response (first 50 bytes): {response[:50].hex()}")
        
        if len(response) >= 48:
            version_bytes = response[44:48]
            major = version_bytes[0]
            minor = version_bytes[1]
            build = (version_bytes[2] << 8) | version_bytes[3]
            
            print(f"[+] {host} - Version: {major}.{minor}.{build}")
            
            if major == 15:
                print(f"[!] SQL Server 2019 - Check build {build}")
            elif major == 13:
                print(f"[!] SQL Server 2016 - Check build {build}")
        else:
            print(f"[-] {host} - Response too short ({len(response)} bytes)")
            
    except socket.timeout:
        print(f"[-] {host} - Timeout after 10 seconds")
    except Exception as e:
        print(f"[-] {host} - Error: {e}")

if __name__ == "__main__":
    targets = ["10.65.54.22", "10.65.54.33", "10.65.54.34", "10.65.54.24", "10.65.54.20"]
    for target in targets:
        get_sql_version(target)
