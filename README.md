# dns_extractor
Script to collect from a Cisco ASA Capture the DNS requests and responses

## Introduction
#cisco #python #automation #scapy #netmiko #devnet #network #firewall #dns

A short time ago Fabien Berarde and myself were working on preparing the segregation of 2 company networks. In the process we had to try and identify all DNS records which would need to be ported over to the new segregated part.

The long way around this, was the scream test: migrate systems over and wait until something doesn't work to identify and add the corresponding record.

But being automation and scripting junkies this solution didn't fit with us. So in this article I'll describe the process and the script that lead us nearly to automation heaven.

## The example architecture  
In our effort to segregate the networks while still enabling users to work as usual we stood up an interconnection with a Cisco ASA firewall between the 2.

The right side of the below diagram is the new segregated network, the left side is the network which we are segregating from.

<IMAGE>

When a client in the new network performs a DNS request to it's DNS Server (10.10.10.10) the server either has authority over the zone and can reply directly or forwards the request to the left DNS for resolution. When the left DNS server has replied, the right DNS server will in turn give the asnwer to the client.

## Sprint #1
### Minimum Viable Product
The premise of the first sprint was that we should be able to capture the traffic between the two DNS servers which would, in theory enable us to extract all the DNS records which don't exist in the new network (and are manifestly usefull since a client is requesting it)

So we setup a capture on the Cisco Firewall as follows :
'''
capture DNS interface inside buffer 33554432 match udp host 10.10.10.10 host 10.20.20.20 eq domain
capture DNS match tcp host 10.10.10.10 host 10.20.20.20 eq domain
'''

Notice we are capturing both UDP and TCP DNS Traffic.

Once the capture had run for a while we export the resulting PCAP for analysis with
'''
copy /pcap capture:DNS scp:/craig@1.1.1.1/DNS.pcap
'''

The destination host 1.1.1.1 will be our Linux workstation in this example.
Opening the Pcap in wireshark enables us to see and requests and responses

<IMAGE>

Interestingly a DNS response contains the query and the answers, so the DNS request in this exercise has no value to us, so we filter on the responses with

<IMAGE>

Which translates to the filter :
'''
dns.flags.response == 1
'''

Now we want to extract the queried record and the answers. Note: In our case we won't be interested in the recursion of CNAME records, we'll take the queried name record and all the associated A records responses found.

To extract the relevant information we add 2 columns found in the packet details

<IMAGE>

Which enables us to have these 2 nice columns with everything we need

<IMAGE>

We export this to CSV through the File > Export Packet Dissections > As CSV, then open it up in Excel and we have our MVP :)

We'll discuss importing the records via Powershell from the CSV at the end of the article

### Sprint conclusion
We demonstrated our capability of capturing and extracting the DNS requests forwarded between our servers, enabling us to manipulate the data for future import via CSV or directly in Excel

### Sprint Backlog
This Sprint proves the point, but is very manual, we want to:

Extract the capture from the firewall automatically
Parse the resulting Pcap into Plain text with only the relevant columns
Import the filtered results into the DNS server


## Sprint #2
### Automatic extraction of the captures
For this part we have multiple possibilities:

Expect script, using Perl, Python or Tcl
Ansible, which we have played with before to perform Cisco associated automations
Pure Python
Our choice was to go with Python using netmiko because of the lead time to having a working demo and our perception of it being easier :)

Netmiko is a Python library which enhances Paramiko to allow us to trivially connect to and manipulate network devices via SSH, (I believe Ansible relies on this also)

Here is the "simple" Netmiko script that replicats what we did manually in the first sprint


from netmiko import ConnectHandler
import time

start_time = time.time()

if __name__ == "__main__":
    asav = {
        "device_type": "cisco_asa",
        "ip": "10.99.99.99",
        "username": 'craig',
        "password": 'CraigS3cureP4ss',
        "secret": '',
        "fast_cli": False
    }


    with ConnectHandler(**asav) as m:
        copy_cap = m.send_command(f'copy /noconfirm /pcap capture:DNS scp://root:root@1.1.1.1/tmp/DNS.pcap', delay_factor=10)
        print("\n------Copy Capture------")
        print(copy_cap)
        time.sleep(0.5)

        clear_capture = m.send_command('clear capture /all')
        print("\n------Clearing Capture------")
        print(clear_capture)
        time.sleep(0.5)

print("\n----Script elasped time: {} seconds".format(time.time() - start_time))
Notice we issue the copy command with the /noconfirm option and the username and password to the SCP server in the url to simplify operations.

Also we don't forget to clear the captures, so that the buffer doesn't fill up to much and we can continue capturing.

Launching this script gives us something like this


------Copy Capture-----
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
5322 packets copied in 7.620 secs (760 packets/sec)



------Clearing Capture------




----Script elasped time: 30.045565843582153 seconds-
Sprint conclusion
Hmm, that was easy :)

Ok not that easy, in reality we encountered multiple issues :

Working from a fresh Centos 7 we only had Python 3.6 available, and Pip installed a version of Netmiko which required Python >=3.7, so we had to downgrade to Netmiko==3.4.0
Working with an ASA in multi-context mode we encountered bug CSCuz66269 ... Which will drive you nuts until you find out its a bug. This bug will always throw a Permission Denied on the SCP copy... We quickly identified it wasn't the SCP server by testing from another device 
But all in all we have a script that will dump the pcaps of the ASA captures in the /tmp folder of our server.

Sprint Backlog
This sprint was pretty straight forward and before going into the project we had this in the back of our minds. For the next step we were going into the unknown

Parse the resulting Pcap into Plain text with only the relevant columns
Import the filtered results into the DNS server
Sprint #3
Automatically Extracting the Pcap information
For this step we delved into Google and found results on Stackoverflow (Aka the dev's Bible) and Github

2 solutions stood out :

StackOverflow: A lot of people mentioned using Tshark to perform the extraction via the command line
 Github: We found a few Gists and repos mainly in Python performing the operations we needed
So we both set out on creating a PoC for each solution, since we didn't have Tshark on our Linux host (Fresh install) and most of the tested repos or didn't gives us the results we wanted or plainly didn't work

(Skipping the Tshark solution since we couldn't install it due to company repo restrictions and taking 2 hours trying to compile it from source only to hit new dependency errors at each compilation trial) 

Note at one point I did suggest finding and running a docker container with a working Tshark in it, but we were already having fun with the next section :)

Python & Scapy
After Googling extensively for how we could trivially manipulate the Pcap in Python we decided to read one of the results we'd previously dismissed: Scapy

We already know the Scapy library as we use it to forge packets, mainly when we are validating firewall flows and application responses, but we had no idea we could also play with pre-recorded traffic.

Scapy enables you to manipulate packets as Python objects and read different layer fields as variables, it also creates simple methods to play within the packets.

Once Scapy is installed on our system here is the first attempt at looking at a DNS Record


craig@linuxhost# scapy
[...]

>>> dns_packets = rdpcap('/tmp/DNS.pcap')
>>> for packet in dns_packets
...  if packet.haslayer(DNS):
...   print(packet.show())
...   break
Which outputs something like








Ajouter un texte alternatif
Aucun texte alternatif pour cette image
Cool No ?

Ok so now we want only the DNS Responses, for this we check if the DNSRR object is present in the packet:


if DNSRR in packet:
So the "full" logic will be 


dns_packets = rdpcap('/tmp/DNS.pcap')
for packet in dns_packets:
 if packet.haslayer(DNS):
  if DNSRR in packet:
   print(packet.show())
   break
Notice the break in the loop, we are just playing with one record to see how to manipulate the objects. This sequence outputs something like this : (Omitting the lower layers)








Ajouter un texte alternatif
Aucun texte alternatif pour cette image
So, as we already saw in the first sprint, the DNS response contains the query and the response data that we need, but while Wireshark will concatenate for us the Address fields of the multiple A records into one comma separated column, Scapy present them as different records.

We need to add some more logic to extract all the "rdata" fields from each resource record of type A and associate them with the "qname" field of the question record. (Because we are not interested in building the CName hierarchy)

The helpful method here is an.count


>>> packet.ancount
6
So we can have something like this:


dns_packets = rdpcap('/tmp/dnsput.pcap')
for packet in dns_packets:
 if packet.haslayer(DNS):
  if DNSRR in packet:
   for i in range(packet.ancount):
    print(f"{packet.qd.qname.decode()};{packet.an[i].rdata}")
    break
Which will output:


www.youtube.com.;b'youtube-ui.l.google.com.'
www.youtube.com.;142.251.42.238
www.youtube.com.;172.217.163.46
www.youtube.com.;172.217.160.78
www.youtube.com.;172.217.160.110
www.youtube.com.;142.251.43.14'
Ok, nearly there, we need to filter only on the A record, we have the record type field for that so with a type == 1 condition we can filter down to just :


www.youtube.com.;142.251.42.238
www.youtube.com.;172.217.163.46
www.youtube.com.;172.217.160.78
www.youtube.com.;172.217.160.110
www.youtube.com.;142.251.43.14
Putting it all together and appending the results to a text file, we get:


dns_packets = rdpcap('/tmp/DNS.pcap')


output = ""


for packet in dns_packets:
 if packet.haslayer(DNS):
  if DNSRR in packet:
   for i in range(packet.ancount):
    if packet.an[i].type == 1:
     output += f"{packet.qd.qname.decode()};{packet.an[i].rdata}\r\n"


f = open("/tmp/DNS_Requests.csv","a+")
f.write(output)
f.close()
Note the .decode() for the qname, in the object the string names are encoded has byte-object

Sprint conclusion
Ok, so this wasn't trivial as we were discovering the objects and methods as we were going along, but the final result is quite satisfying in its simplicity.

In a few lines of code we are able to parse the Pcap, filter on the responses, and extract the records we want into a CSV for further processing.

Sprint Backlog
All we need to do now is manipulate the CSV to our liking, with Excel or with Grep, Sort, Uniq in Linux and then Import the records into the DNS Server via Powershell

Sprint #4
CSV Manipulation
A few cool things we can do quickly with our CSV are


craig@linuxhost# cat /tmp/DNS_Request.csv | sort | uniq | wc -l
6982
Or 


craig@linuxhost# cat /tmp/DNS_Request.csv | grep "youtube" | sort | uniq | wc - l
34
Powershell Import
For this part we did sped to much time trying to find a way to do this from the Linux host, the DNS server is in the Active Directory domain and requires authentication, so the simpliest for us was to manually copy the CSV over and run the following 


$address = import-csv .\DNS_Request.csv -Delimiter ';'


foreach($add in $address){
  Add-DnsServerResourceRecordA -Name '.' -ZoneName $add.name -IPv4Address $add.address -ComputerName DNSSERVER
}
This gives us more control over what we are importing, and since we have automated the rest of the process, we are quite happy with the remaining manual task.

Conclusion
https://github.com/craigarms/dns_extractor

I think, infact I'm pretty sure, we've only scratched the surface of the Scapy Library, but this was a fun and very useful project for us.

Big up to Ghislain BERNARD who helped us with all the user validation and testing, and to my team mate and fellow script junky Fabien Berarde
