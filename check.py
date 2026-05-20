#!/usr/bin/env python3
import socket

def discover_sql_instance(host):
    """Query SQL Server Browser service on UDP 1434"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        # Broadcast request for SQL Server instances
        sock.sendto(b'\x03', (host, 1434))
        data, addr = sock.recvfrom(4096)
        
        # Parse the response (semicolon-delimited)
        decoded = data.decode('utf-16le', errors='ignore')
        parts = decoded.split(';')
        
        # Look for TCP port in the response
        for i, part in enumerate(parts):
            if part.upper() == 'TCP':
                tcp_port = parts[i + 1] if i + 1 < len(parts) else '1433'
                print(f"[+] Found SQL Server on {host}:{tcp_port}")
                return tcp_port
        return '1433'
    except socket.timeout:
        print(f"[-] UDP 1434 timeout on {host} - trying direct TCP")
        return '1433'
    except Exception as e:
        print(f"[-] Discovery failed on {host}: {e}")
        return '1433'

def get_version_tcp(host, port):
    """Now send the TDS pre-login packet to the discovered port"""
    prelogin_packet = bytes([
        0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
        0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03,
        0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
        0x55, 0x00, 0x00, 0x00, 0x4d, 0x53, 0x53, 0x51,
        0x4c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00
    ])
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, int(port)))
        sock.send(prelogin_packet)
        response = sock.recv(1024)
        sock.close()
        
        if len(response) >= 48:
            v = response[44:48]
            major, minor, build_high, build_low = v[0], v[1], v[2], v[3]
            build = (build_high << 8) | build_low
            print(f"[+] {host}:{port} - Version: {major}.{minor}.{build}")
            
            if build in [7080, 4465]:
                print(f"[!] VULNERABLE VERSION DETECTED: {major}.{minor}.{build}")
        else:
            print(f"[-] {host}:{port} - Invalid response ({len(response)} bytes)")
            
    except socket.timeout:
        print(f"[-] {host}:{port} - TCP timeout")
    except Exception as e:
        print(f"[-] {host}:{port} - Error: {e}")

# Main execution
targets = ["10.65.54.22", "10.65.54.33", "10.65.54.34", "10.65.54.24", "10.65.54.20"]

for ip in targets:
    print(f"\n[*] Checking {ip}")
    tcp_port = discover_sql_instance(ip)
    if tcp_port:
        get_version_tcp(ip, tcp_port)
