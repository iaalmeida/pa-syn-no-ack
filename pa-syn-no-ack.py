#!/usr/bin/env python
# -*- coding: latin-1 -*-
'''
Find SYN packets without SYN-ACK in a PCAP file
Usage examples:
    __file__ -i 100 -n 10000 -f 'tcp and not tcp.analysis.out_of_order' /c/TEMP/capture.pcap
'''

import os, sys
import argparse
import pyshark
import progressbar 


# Versioning
__author__ = 'Ivo Almeida'
__version__ = '1.1a'
__maintainer__ = 'Ivo Almeida'
__email__ = 'ivoalm@gmail.pt'

# Global definitions
TCP = '6'
SYN = 0x00000002
SYNACK = 0x00000012
flags = {SYN: 'SYN', SYNACK: 'SYN-ACK'}
flows = { }
stats = dict.fromkeys(['packets', 'syns', 'syn-acks', 'other', 'errors'], 0)
unknowns = [ ]


# Parsing options
parser = argparse.ArgumentParser(description='Find strange SYN / SYN-ACKs flows in a PCAP file')
parser.add_argument('-V', '--version', action='version', version="%(prog)s "+__version__)
parser.add_argument('-f', '--filter', default='tcp', help='tshark display filter')
parser.add_argument('-i', '--initial', type=int, help='first packet number to analyse')
parser.add_argument('-n', '--number', type=int, help='number of events to process')
parser.add_argument('file', default='capture.cap', help='tcpdump file to analyse')
args = parser.parse_args()

#if args.version:
#    print(f'{sys.argv[0]} version {__version__}', file=sys.stderr)
#    exit(0)


def syn_sent(pkt):
    '''received a syn packet'''
    #if not flows[pkt.ip.src][pkt.ip.dst][pkt.tcp.srcport]:  #it's a new flow
    #    flows[pport] = []
    global flows

    #packet from client to server 
    key = '/'.join([ pkt.ip.src, pkt.ip.dst, pkt.tcp.srcport ])
    if not flows.get(key):
        flows[key] = []
    flows[key].append(pkt)  #it's a new flow

#syn_sent()


def syn_ack_received(pkt):
    '''received a syn-ack packet'''
    global flows, unknowns

    #packet from server to client
    key = '/'.join([ pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport ])
    if flows.get(key):
        flows[key].append(pkt)
    else:
        unknowns.append(pkt)

#syn_ack_received()


def print_stats(num):
    ''' prints the stats for this session '''
    global flows

    print_flows()
    print_unknown_flows()
    print('----------' * 10 + "\nSession statistics:")
    if args.filter:
        print(f"  \tfilter used: '{args.filter}'")
    print(f"{args.initial if args.initial else 1:7}\tis the first packet analysed")
    print(f"{num:7}\tpackets read")
    print(f"{stats['packets']:7}\ttotal packets analysed")
    print(f"{len(flows):7}\tconversations found")
    print(f"{len(unknowns):7}\tunknown packets")
    print(f"{stats['syns']:7}\tSYN packets received")
    print(f"{stats['syn-acks']:7}\tSYN-ACK packets received")
    print(f"{stats['other']:7}\tother type of packets received")
    print(f"{stats['errors']:7}\tflows with possible problems")
    
#print_stats()


def print_flows():
    ''' print problematic flows '''
    global flows

    print('----------' * 10 + "\nStrange Flows:")
    for key in flows.keys():
        packets = flows[key]
        if len(packets) > 2 or len(packets) == 2 and packets[0].tcp.flags == packets[1].tcp.flags:  #have to be analysed
            stats['errors'] += 1
            p0 = packets[0]  #initial packet
            print(f'  {stats["errors"]:>4}. {p0.ip.src}:{p0.tcp.srcport} <-> {p0.ip.dst}:{p0.tcp.dstport} \t({len(packets)} packets)')
            for pkt in packets:
                print(f'\t{pkt.frame_info.number:>6}: {pkt.ip.src:>15}  {pkt.ip.dst:15}  {flags[int(pkt.tcp.flags, 16)]}')
    pass  #for debugging help

#print_flows()


def print_unknown_flows():
    ''' print the unknown flows '''
    global unknowns

    if len(unknowns):
        print('----------' * 10 + "\nSYN-ACKs without SYNs:")
    for pkt in unknowns:
        print(f'\t{pkt.frame_info.number:>6}: {pkt.ip.src:>15}:{pkt.tcp.srcport}  {pkt.ip.dst}:{pkt.tcp.dstport}  {flags[int(pkt.tcp.flags, 16)]}')

#print_unknown_flows()


if __name__ == '__main__':
    # Open saved trace file:
    if not os.path.isfile(args.file):
        print(f"'{args.file}' does not exist", file=sys.stderr)
        sys.exit(-1)
    capture = pyshark.FileCapture(args.file, display_filter=args.filter)
    #capture.set_debug()

    bar = progressbar.ProgressBar(max_value = args.number if args.number else progressbar.UnknownLength)
    for num, pkt in enumerate(capture, start=1):
        if args.initial and num < args.initial:  #jump first args.initial packets
            continue
        if args.number and stats['packets'] == args.number:  #max number of packets defined
            capture.close()  #tshark needs to close the input file
            break
        stats['packets'] += 1
        if pkt.ip.proto != TCP:  #to assure it's a TCP packet
            continue
        if int(pkt.tcp.flags, 16) == SYN:  #SYN packet
            stats['syns'] += 1
            syn_sent(pkt)
        elif int(pkt.tcp.flags, 16) == SYNACK:  #SYN-ACK packet
            stats['syn-acks'] += 1
            syn_ack_received(pkt)
        else:
            stats['other'] += 1
            continue
        bar.update(stats['packets'])
    #--- for pkt in capture:
    print_stats(num-1)

#--- main
sys.exit(0)