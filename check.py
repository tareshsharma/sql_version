#!/usr/bin/env python3
import socket
import ssl
import sys

# TDS Pre-Login packet (same as before)
prelogin_packet = bytes([
    0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
    0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03,
    0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
    0x55, 0x00, 0x00, 0x00, 0x4d, 0x53, 0x53, 0x51,
    0x4c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00
])

def get_sql_version_tls(host, port=1433):
    """Connect to SQL Server with TLS support"""
    try:
        print(f"[*] Checking {host}:{port}...")
        
        # Step 1: Create regular socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Step 2: Wrap with SSL/TLS
        # SQL Server typically uses TLS 1.2
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Allow older TLS versions that SQL Server might use
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        
        print(f"[+] Establishing TLS connection...")
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        
        print(f"[+] TLS Version: {ssl_sock.version()}")
        print(f"[+] Cipher: {ssl_sock.cipher()[0]}")
        
        # Step 3: Send TDS pre-login packet over TLS
        print(f"[+] Sending TDS pre-login packet...")
        ssl_sock.send(prelogin_packet)
        
        # Step 4: Receive response
        response = ssl_sock.recv(4096)
        print(f"[+] Received {len(response)} bytes")
        
        ssl_sock.close()
        
        # Step 5: Parse version from response
        if len(response) >= 48:
            version_bytes = response[44:48]
            major = version_bytes[0]
            minor = version_bytes[1]
            build = (version_bytes[2] << 8) | version_bytes[3]
            
            # Map major version to SQL Server release
            versions = {
                15: "SQL Server 2019",
                14: "SQL Server 2017",
                13: "SQL Server 2016",
                12: "SQL Server 2014",
                11: "SQL Server 2012",
                10: "SQL Server 2008"
            }
            
            version_name = versions.get(major, f"SQL Server Unknown ({major})")
            
            result = f"{host}:{port} - {version_name} {major}.{minor}.{build}"
            print(f"[+] {result}")
            
            # Check for vulnerable versions
            if major == 13 and build == 7080:
                print(f"[!] VULNERABLE: SQL Server 2016 13.0.7080.00")
            elif major == 15 and build == 4465:
                print(f"[!] VULNERABLE: SQL Server 2019 15.0.4465.00")
            
            return result
        else:
            print(f"[-] {host}:{port} - Response too short ({len(response)} bytes)")
            return None
            
    except ssl.SSLError as e:
        print(f"[-] {host}:{port} - SSL Error: {e}")
        print(f"[*] Trying non-TLS connection as fallback...")
        return get_sql_version_plain(host, port)
    except socket.timeout:
        print(f"[-] {host}:{port} - Timeout")
        return None
    except ConnectionRefused:
        print(f"[-] {host}:{port} - Connection refused")
        return None
    except Exception as e:
        print(f"[-] {host}:{port} - Error: {e}")
        return None

def get_sql_version_plain(host, port=1433):
    """Fallback: Try without TLS (for older SQL Server versions)"""
    try:
        print(f"[*] Trying plain connection to {host}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        sock.send(prelogin_packet)
        response = sock.recv(4096)
        sock.close()
        
        if len(response) >= 48:
            version_bytes = response[44:48]
            major = version_bytes[0]
            minor = version_bytes[1]
            build = (version_bytes[2] << 8) | version_bytes[3]
            print(f"[+] {host}:{port} - Plain: {major}.{minor}.{build}")
            return f"{major}.{minor}.{build}"
    except Exception as e:
        print(f"[-] Plain connection failed: {e}")
    return None

if __name__ == "__main__":
    # Single IP or multiple IPs from command line
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        # Default targets from your example
        targets = ["10.65.54.22", "10.65.54.33", "10.65.54.34", "10.65.54.24", "10.65.54.20"]
    
    print(f"[*] Scanning {len(targets)} host(s)...")
    print("[*] Using TLS-enabled SQL Server version detection\n")
    
    for target in targets:
        get_sql_version_tls(target)
        print()  # Empty line between results
