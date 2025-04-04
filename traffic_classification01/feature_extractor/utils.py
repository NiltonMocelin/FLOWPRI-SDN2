#scapy doc: https://scapy.readthedocs.io/en/latest/api/scapy.packet.html#scapy.packet.Packet
from scapy.utils import rdpcap, RawPcapReader, RawPcapWriter
from scapy.packet import Packet
from scapy.all import IP, UDP, TCP, Padding, Raw
from scapy.plist import PacketList

import math

#### PKT
def len_pkt(pkt: Packet) -> int:
    return len(pkt.firstlayer()) ## ver se isso tem diferenca

def sent_time(pkt: Packet) -> float:
    return float(sent_time())

def time(pkt: Packet) -> float:
    return float(time())

def len_payload_UDP(pkt: Packet) -> int:
    return len(pkt[UDP] - pkt[UDP].payload)

#### TCP

def len_payload_TCP(pkt: Packet) -> int:
    return len(pkt[TCP].payload)

def len_header_TCP(pkt: Packet) -> int:
    return len(pkt[TCP] - pkt[TCP].payload)

def len_TCP(pkt: Packet) -> int:
    return len(pkt(TCP))

def check_ACK_flag(pkt):
    if 'A' in pkt[TCP].flags:
        return True
    
    return False


def check_SYN_flag(pkt):
    if 'S' in pkt[TCP].flags:
        return True
    
    return False

def check_FYN_flag(pkt):
    if 'F' in pkt[TCP].flags:
        return True
    
    return False

def check_RST_flag(pkt):
    if 'R' in pkt[TCP].flags:
        return True
    
    return False

def contador_flags(lista_flags:list, flag:str = None):
    contador =0
    if flag:
        for val in lista_flags:
            if flag in val:
                contador +=1
    else:
        contador = len(lista_flags)
    return contador

#### calculos base
def calcular_mean(lista_valores):
    if lista_valores == []:
        return 0
    
    soma = 0.0
    for val in lista_valores:
        soma += val
    retorno = soma/len(lista_valores)
    
    return retorno

def calcular_median(lista_valores):
    if lista_valores == []:
        return 0
    
    lista_ordenada = sorted(lista_valores, key = lambda x:float(x))
    
    meio = len(lista_ordenada)/2 -1
    if(int(meio % 2) != 0):     
        return lista_ordenada[int(meio)]

    return (lista_ordenada[int(meio)] + lista_ordenada[int(meio + 1)])/2

def calcular_q1(lista_valores):
    if lista_valores == []:
        return 0
    
    lista_ordenada = sorted(lista_valores, key = lambda x:float(x))
    
    quartil = int(len(lista_ordenada) * 0.25)
    return lista_ordenada[quartil]

def calcular_q3(lista_valores):
    if lista_valores == []:
        return 0
    
    lista_ordenada = sorted(lista_valores, key = lambda x:float(x))
    
    quartil = int(len(lista_ordenada) * 0.75)
    return lista_ordenada[quartil]

def calcular_max(lista_valores):
    if lista_valores == []:
        return 0
    
    max = -999999

    for val in lista_valores:
        if val > max:
            max = val
    return max

def calcular_min(lista_valores):
    if lista_valores == []:
        return 0
    
    min = 999999

    for val in lista_valores:
        if val < min:
            min = val
    return min

def calcular_std(lista_valores):
    if lista_valores == []:
        return 0
    
    return math.sqrt(calcular_var(lista_valores))

def calcular_var(lista_valores):

    if lista_valores == []:
        return 0

    media = calcular_mean(lista_valores)

    soma = 0.0
    for val in lista_valores:
        aux = (val - media)
        soma += aux * aux 
    return soma/len(lista_valores)

def calcular_sum(lista_valores):

    soma = 0
    for val in lista_valores:
        soma+=val

    return soma

def calcular_maior_media(lista_valores):
    if lista_valores == []:
        return 0

    media = calcular_mean(lista_valores)

    somatorio = 0
    for val in lista_valores:
        if val > media:
            somatorio+=1
    return somatorio

def calcular_menor_media(lista_valores):
    if lista_valores == []:
        return 0
    
    media = calcular_mean(lista_valores)

    somatorio = 0
    for val in lista_valores:
        if val < media:
            somatorio+=1
    return somatorio

### outra forma de obter as flags
# FIN = 0x01
# SYN = 0x02
# RST = 0x04
# PSH = 0x08
# ACK = 0x10
# URG = 0x20
# ECE = 0x40
# CWR = 0x80
# And test them like this:

# F = p['TCP'].flags    # this should give you an integer
# if F & FIN:
#     # FIN flag activated
# if F & SYN:
#     # SYN flag activated
# # rest of the flags here