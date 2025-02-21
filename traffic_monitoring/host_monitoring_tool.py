# source: https://python-libpcap.readthedocs.io/en/latest/
# Requirements:
# sudo apt-get install libpcap-dev
# pip install python-libpcap

from pylibpcap.pcap import sniff
from scapy.all import Ether

'tupla-id:lista[(pacote, timestamp)]'
packets_dict = {}


#for plen, t, buf in sniff("enp7s0", filters="port 53", count=-1, promisc=1, out_file="pcap.pcap"):
for plen, t, buf in sniff("enp7s0", count=-1, promisc=0):

    # se for um pacote marcado, busca no dicionario e adiciona
    # se tiver 10, cria uma thread para calcular as métricas >> receber do controlador as métricas dele (sincronizar) calcular a media, enviar a blockchain.

    print(Ether(buf))
    print("[+]: Payload len=", plen)
    print("[+]: Time", t)
    print("[+]: Payload", buf)
