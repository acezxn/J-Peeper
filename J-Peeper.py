#!/usr/bin/env python
import subprocess as sp
import time
from datetime import datetime
import os
import argparse
try:
    from scapy.all import *
except:
    os.system('pip install scapy')
    from scapy.all import *

def arpspoof_sniff(sub):

    lines = os.popen(f'arp {sub}')
    arp_result = ""
    for l in lines:
        arp_result = l.split(" ")[3]


    tmp = []
    for e in arp_result.split(":"):
        inner = ""
        for i in range(2-len(e)):
            inner += "0"
        inner += e
        tmp.append(inner)
    arp_result = ":".join(tmp)

    print("scanner: ", scanner_single(sub))
    scan_result = scanner_single(sub)[0]['mac']

    if scan_result != arp_result:
        print('\n [WARNING] Arp spoofing detected')
        print('\n[INFO] Attackers MAC: {}'.format(arp_result))
    else:
        print('\n [INFO] You are safe!')

def sni_launcher(t, sub):
    while True:
        arpspoof_sniff(sub)
        time.sleep(t)
def sniffer(c):
        packets = sniff(count=c)
        packets.show()

def scanner_single(subnet):
    print("Network scanning in progress")
    area = subnet
    arp = ARP(pdst=area)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    p = ether/arp
    result = srp(p, timeout=10)[0]
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients;
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

def scanner(subnet):
    print("Network scanning in progress")
    area = subnet + "/24"
    arp = ARP(pdst=area)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    p = ether/arp
    result = srp(p, timeout=10)[0]
    clients = []

    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients;
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))


def ui():
    print(chr(27) + "[2J")
    print(
    '''

     ██╗      ██████╗ ███████╗███████╗██████╗ ███████╗██████╗
     ██║      ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗
     ██║█████╗██████╔╝█████╗  █████╗  ██████╔╝█████╗  ██████╔╝
██   ██║╚════╝██╔═══╝ ██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗
╚█████╔╝      ██║     ███████╗███████╗██║     ███████╗██║  ██║
 ╚════╝       ╚═╝     ╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝

                         __..--.._
  .....              .--~  .....  `.
.":    "`-..  .    .' ..-'"    :". `
` `._ ` _.'`"(     `-"'`._ ' _.' '   Find script kiddies over the network~
     ~~~      `.          ~~~        -By Daniel Lee
              .'
             /
            (
             ^---'
    '''
    )
    while True:
        print(
        '''
        Actions:
        1) About the tool
        2) Arpspoof buster
        3) sniffer
        4) Show arp
        5) Quit
        6) scanner
        '''
        )
        opt = input('Insert actions: ')
        if opt == '1':
            print(
            '''
This is a tool for network security. The tool can be used to spot
mitm attackers and got their mac address.
                ''')
            continue
        elif opt == '2':
            t = int(input('Insert duration >> '))
            sub = input('Insert subnet ip >> ')
            sni_launcher(t, sub)
        elif opt == '3':
            sniffer(10)
        elif opt == '4':
            os.system('arp -a')
            continue
        elif opt == '5':
            print('Bye')
            break
        elif opt == '6':
            sub = input('Insert subnet ip >> ')
            client = scanner(sub)
            print(f'ip \t\t mac')
            for c in client:
                print(f"{c['ip']} \t {c['mac']}")
            break
        elif opt == 'clear':
            print(chr(27) + "[2J")
            continue
        try:
            pass
        except Exception as e:
            print('Invalid option', e)
            continue
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--detect', help = 'Detect arp spoofing with duration', type=int)
    parser.add_argument('-s', '--sniff', help = 'Sniffer', type=int)
    args = parser.parse_args()
    if args.detect == None and args.sniff == None:
        ui()
    if args.detect != None:
        sni_launcher(args.detect)
    elif args.sniff != None:
        sniffer(args.sniff)
