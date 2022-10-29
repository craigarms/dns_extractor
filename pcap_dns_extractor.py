from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import os


def extract_dns_from_directory(directory, output_file):
    for filename in os.listdir(directory):
        if '.pcap' in filename:
            f = os.path.join(directory, filename)
            if os.path.isfile(f):
                output = ""
                dns_packets = rdpcap(f)
                for packet in dns_packets:
                    if packet.haslayer(DNS):
                        if DNSRR in packet:
                            if packet.qd.qtype == 1:
                                for i in range(packet.ancount):
                                    if packet.an[i].type == 1:
                                        output += f"{packet.qd.qname.decode()};{packet.an[i].rdata}\r\n"

                f = open(output_file, "a+")
                f.write(output)
                f.close()


if __name__ == '__main__':
    directory = '/tmp/'
    output_file = "/tmp/DNS_Request.csv"
    extract_dns_from_directory(directory, output_file)
