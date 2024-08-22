import socket

def get_service_banner(ip, port):
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        
        # Connect to the port
        sock.connect((ip, port))
        
        # Try to receive the banner
        banner = sock.recv(1024).decode().strip()
        return banner
    except:
        return None
    finally:
        sock.close()

def scan_tcp_port(ip, port):
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        
        # Attempt to connect to the target IP and TCP port
        result = sock.connect_ex((ip, port))
        if result == 0:
            return True  # TCP Port is open
        else:
            return False  # TCP Port is closed
    except socket.error:
        return False
    finally:
        sock.close()

def scan_udp_port(ip, port):
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        
        # Sending an empty UDP packet to the target IP and port
        sock.sendto(b'', (ip, port))
        
        # Attempt to receive a response (if any)
        try:
            data, _ = sock.recvfrom(1024)
            return True  # UDP Port is open
        except socket.timeout:
            return False  # UDP Port might be open (no response could mean it's open)
        except socket.error:
            return False  # UDP Port is closed
    finally:
        sock.close()

def scan_ports(ip, num_ports):
    open_tcp_ports = []
    open_udp_ports = []
    print(f"Scanning {ip} for open TCP and UDP ports...")

    for port in range(1, num_ports + 1):  # Scanning ports from 1 to the user-specified range
        if scan_tcp_port(ip, port):
            banner = get_service_banner(ip, port)
            if banner:
                print(f"Port {port} is open (TCP) - Service: {banner}")
            else:
                print(f"Port {port} is open (TCP)")
            open_tcp_ports.append(port)
        
        if scan_udp_port(ip, port):
            print(f"Port {port} is open (UDP)")
            open_udp_ports.append(port)
    
    if open_tcp_ports:
        print(f"\nOpen TCP ports on {ip}: {open_tcp_ports}")
        
    if open_udp_ports:
        print(f"\nOpen UDP ports on {ip}: {open_udp_ports}")

if __name__ == "__main__":
    target_ip = input("Enter the IP address to scan: ")
    
    # Prompt the user for the number of ports to scan
    while True:
        try:
            num_ports = int(input("Enter the number of ports to scan (between 10 and 1000): "))
            if 10 <= num_ports <= 1000:
                break
            else:
                print("Please enter a number between 10 and 1000.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")
    
    scan_ports(target_ip, num_ports)

