from netmiko import ConnectHandler
import time
import calendar
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR

start_time = time.time()  # start time to execute the python script.

if __name__ == "__main__":
    current_GMT = time.gmtime()
    ts = calendar.timegm(current_GMT)
    filename = f"{ts}_dnsput.pcap"
    output = ""

    asav = {
        "device_type": "cisco_asa",
        "ip": "10.99.99.99",
        "username": 'craig',
        "password": 'craig',
        "secret": '',
        "fast_cli": False
    }

    with ConnectHandler(**asav) as m:
        system_ctx = m.send_command(f'copy /noconfirm /pcap capture:dnsput scp://root:root@1.1.1.1/tmp/{filename}',
                                    delay_factor=10)
        print("\n------Copy Capture------")
        print(system_ctx)
        time.sleep(0.5)
        clear_capture = m.send_command('clear capture /all')
        print("\n------Clearing Capture------")
        print(clear_capture)
        time.sleep(0.5)

    dns_packets = rdpcap(f'/tmp/{filename}')
    for packet in dns_packets:
        if packet.haslayer(DNS):
            if DNSRR in packet:
                if packet.qd.qtype == 1:
                    for i in range(packet.ancount):
                        if packet.an[i].type == 1:
                            output += f"{packet.qd.qname.decode()};{packet.an[i].rdata}\r\n"

    f = open("/tmp/DNS_Request.csv", "a+")
    f.write(output)
    f.close()

# time takes to finish the entire script.
print("\n----Script elasped time: {} seconds".format(time.time() - start_time))
