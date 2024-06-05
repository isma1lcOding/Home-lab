from scapy.all import ARP, Ether, srp  # Import necessary modules from scapy library
import socket  # Import the socket module
import struct  # Import the struct module
import fcntl  # Import the fcntl module


# Basic user interface header
print(r"""______            _     _  ______                 _           _ 
 ___                     _ _    ____  ____      _ _             
        |_ _|___ _ __ ___   __ _(_) |  / ___|/ __ \  __| (_)_ __   __ _ 
         | |/ __| '_ ` _ \ / _` | | | | |   / / _` |/ _` | | '_ \ / _` |
         | |\__ \ | | | | | (_| | | | | |__| | (_| | (_| | | | | | (_| |
        |___|___/_| |_| |_|\__,_|_|_|  \____\ \__,_|\__,_|_|_| |_|\__, |
                                             \____/               |___/ 
         _____            _     _  ______                 _           _ 
""")
print("\n* Home LAB   Practice 2024                           *")
print("\n****************************************************************")


def get_local_ip(iface):
    """Function to get the IP address of the specified network interface"""
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Get the IP address of the specified network interface
    ip = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', iface[:15].encode('utf-8')))[20:24])
    return ip

def get_network_prefix(ip):
    """Function to get the network prefix from the local IP address"""
    return '.'.join(ip.split('.')[:-1]) + '.'

def resolve_hostname(ip):
    """Function to resolve the hostname associated with an IP address"""
    try:
        # Attempt to get the hostname associated with the IP address
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        # Return "N/A" if the hostname cannot be resolved
        return "N/A"

def scan_network(prefix):
    """Function to scan the network for connected devices"""
    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=prefix + "1/24")
    # Send the ARP request packet and get the response
    result = srp(arp_request, timeout=2, verbose=0)[0]
    # Create a list of dictionaries containing information about each device
    devices = [{'ip': received.psrc, 'mac': received.hwsrc, 'hostname': resolve_hostname(received.psrc)} for sent, received in result]
    return devices

def main():
    """Main function"""
    # Prompt the user to choose a network interface
    iface = input("Enter the network interface (eth0 or wlan0): ")
    # Ensure the input is either "eth0" or "wlan0"
    while iface not in ["eth0", "wlan0"]:
        iface = input("Invalid interface. Enter either eth0 or wlan0: ")
    # Get the network prefix from the local IP address
    prefix = get_network_prefix(get_local_ip(iface))
    print(f"Scanning network with prefix: {prefix}")
    # Scan the network to find connected devices
    devices = scan_network(prefix)
    print("Available devices in the network:")
    print("IP" + " "*18 + "MAC" + " "*18 + "Hostname")
    for device in devices:
        # Print information about each device
        print(f"{device['ip']:16}    {device['mac']}    {device['hostname']}")

if __name__ == "__main__":
    main()
