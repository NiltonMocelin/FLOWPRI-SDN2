# source: https://python-libpcap.readthedocs.io/en/latest/
# Requirements:
# sudo apt-get install libpcap-dev
# pip install python-libpcap

from pylibpcap.pcap import sniff
from scapy.all import Ether

'tupla-id:lista[(pacote, timestamp)]'
packets_dict = {}


#for plen, t, buf in sniff("enp7s0", filters="port 53", count=-1, promisc=1, out_file="pcap.pcap"):
# for plen, t, buf in sniff("eth0", filters="(ip and (ip[1] & 0xfc) >> 2 == 20)", count=-1, promisc=0):
# dscp filter base: http://darenmatthews.com/blog/?p=1199 (same as in tcpdump)

# replicating for flow label (ipv6)
# ipv6 flow label is the bits from 12-20 ;; ipv6 flow class is from bits 4-8 (we are using the flow label bits for marking packets for classification)
# filters = "(ip and (ip[]))" ---> as we use the number 7 as the mark in the packets, we just need to check the first 3 bits of the flow label

# IPV6 header (small frame)
# |   1   2  3  4  |       5  6  7 8 1 2 3 4     |5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8|
# |--------------------------------------------------------------------------------------|
# |  version (4)   | Traffic class (8)           |               Flow label (20)         |
# |--------------------------------------------------------------------------------------|

# we can just take the 3th byte of the header (16-32), then, compare to the mask of the bitlike 7 (0111)(actually, unnecessary)
# filters = "(ip and ip[3]  == 0x7)"
# for plen, t, buf in sniff("eth0", filters="(ip and ip[3]  == 0x7) ", count=-1, promisc=0):
for plen, t, buf in sniff("eth0", filters="(ip and ip[3]  == 0x7) ", count=-1, promisc=0):

    # se for um pacote marcado, busca no dicionario e adiciona
    # se tiver 10, cria uma thread para calcular as métricas >> receber do controlador as métricas dele (sincronizar) calcular a media, enviar a blockchain.

    # checar tos ipv4 ou flowlabel ipv6, se for QoSMONITORING, armazenar em um pcap

    # se tiver 20 pacotes nesse arquivo, extrair features para calculo

    print(Ether(buf))
    print("[+]: Payload len=", plen)
    print("[+]: Time", t)
    print("[+]: Payload", buf)

# uma thread para ler qos monitoring json dos domínios.
