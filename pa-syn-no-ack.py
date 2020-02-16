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
__version__ = '1.2a'
__maintainer__ = 'Ivo Almeida'
__email__ = 'ivoalm@gmail.pt'

# Global definitions
TCP = '6'
SYN = 0x02
SYNACK = 0x12
SYNACKECN = 0x52
SYNECECWR = 0xc2
flows = { }
stats = dict.fromkeys(['packets', 'syns', 'syn-acks', 'other', 'errors'], 0)
tcp_flags = {
    SYN: '> SYN', SYNACK: '< SYN-ACK', SYNACKECN: '< SYN-ACK-ECN', SYNECECWR: '> SYN-ECE-CWR'
}


unknowns = [ ]


# Parsing options
parser = argparse.ArgumentParser(description='Find strange SYN / SYN-ACKs flows in a PCAP file')
parser.add_argument('-V', '--version', action='version', version="%(prog)s "+__version__)
parser.add_argument('-f', '--filter', help='tshark display filter')
parser.add_argument('-i', '--initial', type=int, help='first packet number to analyse')
parser.add_argument('-n', '--number', type=int, help='number of events to process')
parser.add_argument('file', default='capture.cap', help='tcpdump file to analyse')
args = parser.parse_args()

#if args.version:
#    print(f'{sys.argv[0]} version {__version__}', file=sys.stderr)
#    exit(0)


def flags(flag):
    ''' returns a flag's name '''
    ''' see http://rapid.web.unc.edu/resources/tcp-flag-key/'''
    global tcp_flags

    if tcp_flags.get(int(flag, 16)):
        return tcp_flags[int(flag, 16)]
    return flag

#flags()


def filter():
    '''sets the diplay filter to use in pyshark, based on initial arguments'''

    f = "tcp"
    if args.initial:
        f += f' and frame.number >= {args.initial}'
    if args.filter:
        f += f' and {args.filter}'
    return f

#filter()


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
    if not flows.get(key):
        unknowns.append(pkt)
    elif len(flows[key]) == 1 and int(flows[key][0].tcp.flags, 16) == SYN and int(pkt.tcp.flags, 16) == SYNACK:
        flows[key].clear()  #this flow is ok
    else:
        flows[key].append(pkt)

#syn_ack_received()


def print_stats():
    ''' prints the stats for this session '''
    global flows

    print_flows()
    print_unknown_flows()
    print('----------' * 10 + "\nSession statistics:")
    if args.filter:
        print(f"  \tfilter used: '{args.filter}'")
    print(f"{args.initial if args.initial else 1:7}\tis the first packet analysed")
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
    print(f'\t{"No.":>6}  {"Time":>8}  {"Source":>15}  {"Dst":<15}  Flags')
    print('----------' * 10)
    for key in flows.keys():
        packets = flows[key]
        if len(packets) > 2 or len(packets) == 2 and packets[0].tcp.flags == packets[1].tcp.flags:  #have to be analysed
            stats['errors'] += 1
            p0 = packets[0]  #initial packet
            print(f'  {stats["errors"]:>4}. {p0.ip.src+":"+p0.tcp.srcport:21} <-> {p0.ip.dst+":"+p0.tcp.dstport:<21}  ({len(packets)} packets)')
            for pkt in packets:
                print(f'\t{pkt.frame_info.number:>7}: {float(pkt.frame_info.time_relative):>11.06f}  {pkt.ip.src:>15}  {pkt.ip.dst:<15}  {flags(pkt.tcp.flags)}')
    pass  #for debugging help

#print_flows()


def print_unknown_flows():
    ''' print the unknown flows '''
    global unknowns

    if len(unknowns):
        print('----------' * 10 + "\nSYN-ACKs without SYNs:")
    for pkt in unknowns:
        print(f'\t{pkt.frame_info.number:>6}: {pkt.ip.src+":"+pkt.tcp.srcport:>21}  {pkt.ip.dst+":"+pkt.tcp.dstport:<21}  {flags(pkt.tcp.flags)}')

#print_unknown_flows()


if __name__ == '__main__':
    # Open saved trace file:
    if not os.path.isfile(args.file):
        print(f"'{args.file}' does not exist", file=sys.stderr)
        sys.exit(-1)

    bar = progressbar.ProgressBar(max_value = args.number or progressbar.UnknownLength)
    capture = pyshark.FileCapture(args.file, display_filter=filter())
    #capture.set_debug()
    try:
        for pkt in capture:
            if args.number and stats['packets'] == args.number:  #max number of packets defined
                capture.close()  #tshark needs to close the input file
                break
            stats['packets'] += 1
            if pkt.ip.proto != TCP or not int(pkt.tcp.flags, 16) & SYN:  #not a TCP neither a SYN kind packet 
                stats['other'] += 1
                continue
            if  int(pkt.tcp.flags, 16) & SYNACK == SYNACK:  #SYN-ACK type packet
                stats['syn-acks'] += 1
                syn_ack_received(pkt)
            else:  #int(pkt.tcp.flags, 16) == SYN:  #SYN type packet
                stats['syns'] += 1
                syn_sent(pkt)
            bar.update(stats['packets'])
        #--- for pkt in capture:
    except KeyboardInterrupt:  #not working for now :(
        print(f'\nCaught a KeyboardInterrupt. Quitting ....')
    finally:
        capture.close()
    print_stats()

#--- main
sys.exit(0)