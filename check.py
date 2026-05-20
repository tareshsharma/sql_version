# Create a new directory
mkdir sql-version-checker
cd sql-version-checker

# Create the script file
cat > sql_version_check.py << 'EOF'
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.send(prelogin_packet)
        response = sock.recv(1024)
        sock.close()
        if len(response) >= 48:
            version_bytes = response[44:48]
            major = version_bytes[0]
            minor = version_bytes[1]
            build = (version_bytes[2] << 8) | version_bytes[3]
            if major == 15:
                version_str = f"SQL Server 2019 {major}.{minor}.{build}"
            elif major == 13:
                version_str = f"SQL Server 2016 {major}.{minor}.{build}"
            else:
                version_str = f"SQL Server {major}.{minor}.{build}"
            print(f"{host}:{port} - {version_str}")
            return version_str
    except Exception as e:
        print(f"{host}:{port} - Error: {e}")
    return None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for ip in sys.argv[1:]:
            get_sql_version(ip)
    else:
        targets = ["10.65.54.22", "10.65.54.33", "10.65.54.34", "10.65.54.24", "10.65.54.20"]
        for target in targets:
            get_sql_version(target)
EOF

# Initialize git and push to GitHub
git init
git add sql_version_check.py
git commit -m "Add SQL Server version checker"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/sql-version-checker.git
git push -u origin main
