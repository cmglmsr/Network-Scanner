#!/usr/bin/env python

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest='target', help="Target IP address or range")
    options = parser.parse_args()[0]
    if not options.target:
        print("[-] Please enter an IP address/range.")
        exit()
    else:
        return options.target


def scan(ip):
    # Imitating scapy.arping(ip) function here
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    ans_list = []
    for ans in answered:
        ans_dict = {"ip": ans[1].psrc, "mac": ans[1].hwsrc}
        ans_list.append(ans_dict)
    return ans_list


def report( ans_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------------------------")
    for ans in ans_list:
        print(ans["ip"] + "\t\t" + ans["mac"])


ip = get_arguments()
result_list = scan(ip)
report(result_list)
