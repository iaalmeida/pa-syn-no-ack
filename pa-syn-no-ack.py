#!/usr/bin/env python
# -*- coding: latin-1 -*-
'''
Find SYN packets without ACK in a PCAP file
Usage examples:
    --file__ -i 100 -n 1000 -f 'tcp and not tcp.analysis.out_of_order' /c/TEMP/capture.cap
'''

import os, sys
import argparse
import pyshark
import progressbar 


# Versioning
__author__ = 'Ivo Almeida'
__version__ = '1.0a'
__maintainer__ = 'Ivo Almeida'
__email__ = 'ivoalm@gmail.pt'

# Global definitions
SYN = '0x00000002'
SYNACK = '0x00000012'
flags = {SYN: 'SYN', SYNACK: 'SYN-ACK'}
flows = { }
stats = dict.fromkeys(['packets', 'syns', 'syn-acks', 'errors'], 0)
unknowns = [ ]


# Parsing options
parser = argparse.ArgumentParser(description='Find strange SYN / SYN-ACKs flows in a PCAP file')
parser.add_argument('-V', '--version', action='store_true', help='show version')
parser.add_argument('-f', '--filter', default='tcp', help='tshark display filter')
parser.add_argument('-i', '--initial', type=int, help='first packet number to analyse')
parser.add_argument('-n', '--number', type=int, help='number of events to process')
parser.add_argument('file', help='tcpdump file to analyse')
args = parser.parse_args()

if args.version:
    print(f'{sys.argv[0]} version {__version__}', file=sys.stderr)
    exit(0)


def print_stats():
    ''' prints the stats for this session '''
    global flows

    print_flows()
    print_unknown_flows()
    print('----------' * 10 + "\nSession statistics:")
    print(f"  {args.initial if args.initial else 1}\tfirst packet analysed")
    print(f"  {stats['packets']}\ttotal packets analysed")
    print(f"  {len(unknowns)}\ttotal unknown flows")
    print(f"  {stats['syns']}\ttotal SYN packets received")
    print(f"  {stats['syn-acks']}\ttotal SYN-ACK packets received")
    print(f"  {stats['errors']}\ttotal error flows")
    
#--- 


def print_flows():
    ''' print problematic flows '''
    global flows

    print('----------' * 10 + "\nStrange Flows:")
    for key in flows.keys():
        packets = flows[key]
        if len(packets) > 2 or len(packets) == 2 and packets[0].tcp.flags == packets[1].tcp.flags:  #case to be analysed
            stats['errors'] += 1
            p0 = packets[0]  #initial packet
            print(f'  {p0.ip.src}:{p0.tcp.srcport} \t{p0.ip.dst}:{p0.tcp.dstport} \t({len(packets)} packets)')
            for pkt in packets:
                print(f'\t{pkt.frame_info.number}: \t{pkt.ip.src} \t{pkt.ip.dst} \t{flags[pkt.tcp.flags]}')
    pass  #for debugging help

#---


def print_unknown_flows():
    ''' print the unknown flows '''
    global unknowns

    if len(unknowns):
        print('----------' * 10 + "\nUnknown Flows:")
    for flow in unknowns:
        print('  ' + flow)

#print_unknown_flows()


def syn_sent(pkt):
    '''received a syn packet'''
    #if not flows[pkt.ip.src][pkt.ip.dst][pkt.tcp.srcport]:  #it's a new flow
    #    flows[pport] = []
    global flows

    #packet from client to server 
    stats['syns'] += 1
    key = '/'.join([ pkt.ip.src, pkt.ip.dst, pkt.tcp.srcport ])
    if not flows.get(key):
        flows[key] = []
    flows[key].append(pkt)  #it's a new flow

#syn_sent()


def syn_ack_received(pkt):
    '''received a syn-ack packet'''
    global flows, unknowns

    #packet from server to client
    stats['syn-acks'] += 1
    key = '/'.join([ pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport ])
    if flows.get(key):
        flows[key].append(pkt)
    else:
        unknowns.append(f'#{pkt.frame_info.number}: {pkt.ip.src}:{pkt.tcp.srcport} -> {pkt.ip.dst}:{pkt.tcp.dstport}')

#syn_ack_received()


if __name__ == '__main__':
    # Open saved trace file:
    if not os.path.isfile(args.file):
        print(f"'{args.file}' does not exist", file=sys.stderr)
        sys.exit(-1)
    capture = pyshark.FileCapture(args.file, display_filter=args.filter)

    bar = progressbar.ProgressBar(max_value = args.number if args.number else progressbar.UnknownLength)
    for num, pkt in enumerate(capture, start=1):
        if args.initial and num < args.initial:
            continue
        if args.number and stats['packets'] == args.number:
            capture.close()  #tshark needs to close the input file
            break
        if (pkt.tcp.flags != SYN and pkt.tcp.flags != SYNACK):  #not a SYN neither SYN-ACK
            continue
        if pkt.tcp.flags == SYN:
            syn_sent(pkt)
        elif pkt.tcp.flags == SYNACK:
            syn_ack_received(pkt)
        else:
            #wtf?!
            unknowns.append(f'#{pkt.frame_info.number}: {pkt.ip.src}:{pkt.tcp.srcport} -> {pkt.ip.dst}:{pkt.tcp.dstport}, this is a non interesting packet')
        bar.update(stats['packets'])
        stats['packets'] += 1
    #--- for pkt in capture:
    print_stats()

#--- main
sys.exit(0)