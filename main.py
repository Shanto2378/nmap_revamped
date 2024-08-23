import socket
import scapy.all as scapy
import prettytable

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "name": socket.getfqdn(element[1].psrc)  # Get device name using the IP address
        }
        devices.append(device)
    return devices

def display_devices(devices):
    table = prettytable.PrettyTable()
    table.field_names = ["Device Name", "IP Address", "MAC Address"]
    table.align = "l"  # Left align columns
    table.max_width = 20  # Set a maximum width for each column to avoid disorganization

    for device in devices:
        table.add_row([device["name"], device["ip"], device["mac"]])
    print(table)

def get_service_banner(ip, port, protocol='tcp'):
    try:
        if protocol == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            return None
        
        sock.settimeout(2)
        
        if protocol == 'tcp':
            sock.connect((ip, port))
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            banner = sock.recv(1024).decode().strip()

            if not banner:
                sock.sendall(b"\n")
                banner = sock.recv(1024).decode().strip()
                if not banner:
                    sock.sendall(b"HELP\r\n")
                    banner = sock.recv(1024).decode().strip()
                    
        else:
            sock.sendto(b'\x00', (ip, port))
            data, _ = sock.recvfrom(1024)
            banner = data.decode().strip()
        
        return banner
    except socket.gaierror:
        print(f"Error: Unable to resolve IP address {ip}")
        return None
    except:
        return None
    finally:
        sock.close()

def scan_tcp_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        return result == 0
    except socket.error:
        return False
    finally:
        sock.close()

def scan_udp_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b'\x00', (ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False
        except socket.error:
            return False
    finally:
        sock.close()

def get_service_name(port, protocol='tcp'):
    try:
        return socket.getservbyport(port, protocol)
    except:
        return None

def extract_specific_fields(banner):
    specific_fields = {}
    lines = banner.split('\n')
    remaining_banner = []

    for line in lines:
        if line.startswith("Date:"):
            specific_fields['Date'] = line
        elif line.startswith("Server:"):
            specific_fields['Server'] = line
        elif line.startswith("X-Powered-By:"):
            specific_fields['X-Powered-By'] = line
        elif line.startswith("Content-Type:"):
            specific_fields['Content-Type'] = line
        else:
            remaining_banner.append(line)

    return specific_fields, "\n".join(remaining_banner).strip()

def scan_ports(ip, num_ports):
    table = prettytable.PrettyTable()
    table.field_names = ["Port", "Service", "Version", "Protocol"]
    table.align = "l"  # Left align columns
    table.max_width = 40  # Set a maximum width for each column to keep things organized
    detailed_info = []

    print(f"Scanning {ip} for open TCP and UDP ports...\n")

    for port in range(1, num_ports + 1):
        # TCP Port Scanning
        if scan_tcp_port(ip, port):
            service_name = get_service_name(port, 'tcp')
            banner = get_service_banner(ip, port, 'tcp')
            if banner:
                specific_fields, remaining_banner = extract_specific_fields(banner)
                table.add_row([port, service_name or 'Unknown', remaining_banner or 'N/A', 'TCP'])
                detailed_info.append(specific_fields)
            else:
                table.add_row([port, service_name or 'Unknown', 'N/A', 'TCP'])
        
        # UDP Port Scanning
        if scan_udp_port(ip, port):
            service_name = get_service_name(port, 'udp')
            banner = get_service_banner(ip, port, 'udp')
            if banner:
                specific_fields, remaining_banner = extract_specific_fields(banner)
                table.add_row([port, service_name or 'Unknown', remaining_banner or 'N/A', 'UDP'])
                detailed_info.append(specific_fields)
            else:
                table.add_row([port, service_name or 'Unknown', 'N/A', 'UDP'])
    
    if table.rowcount > 0:
        print(table)
        for fields in detailed_info:
            for key, value in fields.items():
                print(value)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    # Step 1: Allow user to input the subnet
    subnet = input("Enter the subnet to scan (e.g., 192.168.1.0/24): ")
    print(f"Scanning the subnet: {subnet}")

    # Step 2: Discover devices on the subnet
    devices = scan_network(subnet)
    if devices:
        print("\nDevices found on the subnet:")
        display_devices(devices)
    else:
        print("No devices found on the subnet.")
        exit()

    # Step 3: Allow the user to select a device for port scanning
    target_ip = input("\nEnter the IP address of the device to scan: ")

    while True:
        try:
            num_ports = int(input("Enter the number of ports to scan (between 10 and 1000): "))
            if 10 <= num_ports <= 1000:
                break
            else:
                print("Please enter a number between 10 and 1000.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")
    
    # Step 4: Run the port scan on the selected device
    scan_ports(target_ip, num_ports)
