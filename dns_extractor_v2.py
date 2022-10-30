import time
import calendar
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import argparse

""" Function that requests user to input username and password """
def get_credentials():
    username = input("Enter username: ")
    password = input("Enter password: ")
    return username, password


""" Function that requests user to input IP address of ASA """
def get_ip():
    ip = input("Enter IP address of ASA: ")
    return ip


""" Function that requests user to input the name of the capture file """
def get_filename():
    filename = input("Enter the name of the destination capture file: ")
    return filename


""" Function that requests user to input the name of the capture """
def get_capture():
    capture = input("Enter the name of the capture: ")
    return capture

""" Function that requests user to input SCP Path """
def get_scp():
    scp = input("Enter the SCP path to copy the capture file: ")
    return scp


""" Function that parses the command line arguments """
def parse_args():
    parser = argparse.ArgumentParser(description="Script to extract DNS requests from a PCAP file")
    parser.add_argument("-u", "--username", help="Username to connect to ASA")
    parser.add_argument("-p", "--password", help="Password to connect to ASA")
    parser.add_argument("-i", "--ip", help="IP address of ASA")
    parser.add_argument("-f", "--filename", help="Name of the capture file")
    parser.add_argument("-c", "--capture", help="Name of the capture file")
    parser.add_argument("-s", "--scp", help="SCP Path to copy the capture file")
    parser.add_argument("-o", "--output", help="Name of the output file")
    args = parser.parse_args()
    return args


""" Function that connects to the ASA and sends the copy command to copy the PCAP file to the local machine """
def copy_pcap_file(username, password, ip, capture, filename, scp):
    asav = {
        "device_type": "cisco_asa",
        "ip": ip,
        "username": username,
        "password": password,
        "secret": '',
        "fast_cli": False
    }
    try:
        with ConnectHandler(**asav) as m:
            copy_capture = m.send_command(f'copy /noconfirm /pcap capture:{capture} scp://{scp}/{filename}',
                                          delay_factor=10)
            time.sleep(0.5)
            clear_capture = m.send_command(f'clear capture {capture}')
            time.sleep(0.5)
    except:
        print("Error: Unable to connect to ASA or copy the capture file")
        print(copy_capture)
        print(clear_capture)
        return False
    return True


""" Function that parses the PCAP file and extracts the DNS requests """
def parse_pcap_file(filename):
    dns_packets = rdpcap(filename)
    output = ""
    for packet in dns_packets:
        if packet.haslayer(DNS):
            if DNSRR in packet:
                if packet.qd.qtype == 1:
                    for i in range(packet.ancount):
                        if packet.an[i].type == 1:
                            output += f"{packet.qd.qname.decode()};{packet.an[i].rdata}\r\n"
    return output


""" Function that writes the DNS requests to a CSV file """
def write_to_csv(output, filename):
    f = open(filename, "a+")
    f.write(output)
    f.close()


""" Main function """
def main():
    args = parse_args()
    if args.username:
        username = args.username
    else:
        username, password = get_credentials()
    if args.password:
        password = args.password
    else:
        username, password = get_credentials()
    if args.ip:
        ip = args.ip
    else:
        ip = get_ip()
    if args.filename:
        filename = args.filename
    else:
        filename = get_filename()
    if args.capture:
        capture = args.capture
    else:
        capture = get_capture()
    if args.scp:
        scp = args.scp
    else:
        scp = get_scp()
    if args.output:
        output_file = args.output
    else:
        output_file = "DNS_Requests.csv"
    if copy_pcap_file(username, password, ip, capture, filename, scp):
        output = parse_pcap_file(filename)
        write_to_csv(output, output_file)
        print("DNS requests extracted successfully")
    else:
        print("Error: Unable to extract DNS requests")