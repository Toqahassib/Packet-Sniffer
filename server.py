import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import datetime
from tabulate import tabulate

# list to store the packet in
packet_list = []

# function to sniff packet on a particular interface using the packets function


def sniffing(interface):
    scapy.sniff(iface=interface, prn=packets)

# function to specify how to sniff packets


def packets(packet):
    time = datetime.datetime.now()

    if answer == '1':
        # sniffs tcp packets
        if packet.haslayer(TCP):
            # store the packets information in a list
            packet_info = [str(time), len(packet[TCP]), str(packet.src), str(packet.dst), str(
                packet.sport), str(packet.dport), str(packet[IP].src), str(packet[IP].dst)]

            # append the packet_info list in the packet_list
            packet_list.append(packet_info)

            # prints the list in a table format
            print(tabulate(packet_list, headers=[
                  'TIME', 'BYTES', 'SRC-MAC', 'DST-MAC', 'SRC-PORT', 'DST-PORT', 'SRC-IP', 'DST-IP'], showindex=len(packet_list), tablefmt='fancy_grid'))

    elif answer == '2':
        # sniffs udp packets
        if packet.haslayer(UDP):

            # store the packets information in a list
            packet_info = [str(time), len(packet[UDP]), str(packet.src), str(packet.dst), str(
                packet.sport), str(packet.dport), str(packet[IP].src), str(packet[IP].dst)]

            # append the packet_info list in the packet_list
            packet_list.append(packet_info)

            # prints the list in a table format
            print(tabulate(packet_list, headers=[
                  'Time', 'BYTES', 'SRC-MAC', 'DST-MAC', 'SRC-PORT', 'DST-PORT', 'SRC-IP', 'DST-IP'], showindex=len(packet_list), tablefmt='fancy_grid'))


# takes user input to filter packets by protocl
print("\nChoose the type of packets:\n\n1: TCP\n2: UDP\n")
answer = input('1 or 2: ')

# input validation
while True:
    if answer not in ('1', '2'):
        print("Please choose 1 or 2.")
        print("\nChoose the type of packets:\n\n1: TCP\n2: UDP\n")
        answer = input('1 or 2: ')
    else:
        break


if __name__ == '__main__':
    sniffing('en0')
