### controlador com addRegrasM e novo GBAM


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet, ether
#from ryu.ofproto import ofproto_v1_5 as ofproto15
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
#
from ryu.lib.packet import in_proto
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4, arp, icmp

from ryu.topology import event

#montar grafo da rede
import networkx as nx
import copy

#socket e thread
import socket
from threading import Thread

#tratar json
import json
import unicodedata

from ryu.lib.ovs import vsctl #ovs-vsctl permite conversar com o protocolo OVSDB

#lidar com bytes
import struct

#tratar tempo - monotonic clock -> round(time.monotonic()*1000)
import time
import datetime
##prints logging - logging.info('tempo atual %d\n' % (round(time.monotonic()*1000)))
import logging

############################################
#       Tabela de traducao de enderecos de controladores (para burlar o uso da mesma tabela (route) e forcar o encaminhamento pela interface correta)
#  CADA CONTROLADOR TEM A SUA (caso seja apenas dois controladores, nao tem problema)
TC = {}
TC['10.123.123.1'] = '10.10.10.1'
TC['10.123.123.2'] = '10.10.10.2'
TC['10.123.123.3'] = '10.10.10.3'
TC['10.123.123.4'] = '10.10.10.4'
TC['10.123.123.5'] = '10.10.10.5'
TC['10.10.10.3'] = '10.123.123.3'
TC['10.10.10.2'] = '10.123.123.2'
TC['10.10.10.3'] = '10.123.123.3'
TC['10.10.10.4'] = '10.123.123.4'
TC['10.10.10.5'] = '10.123.123.5'
TC['20.10.10.3'] = '10.10.10.3'
TC['20.10.10.2'] = '10.10.10.2'
TC['20.10.10.4'] = '10.10.10.4'
TC['20.10.10.5'] = '10.10.10.5'
TC['20.20.20.1'] = '10.10.10.1'
TC['20.20.20.3'] = '10.10.10.3'
TC['20.20.20.4'] = '10.10.10.4'
TC['20.20.20.5'] = '10.10.10.5'
TC['20.30.30.1'] = '10.10.10.1'
TC['20.30.30.2'] = '10.10.10.2'
TC['20.30.30.4'] = '10.10.10.4'
TC['20.30.30.5'] = '10.10.10.5'
TC['20.40.40.1'] = '10.10.10.1'
TC['20.40.40.2'] = '10.10.10.2'
TC['20.40.40.3'] = '10.10.10.3'
TC['20.40.40.5'] = '10.10.10.5'
TC['20.50.50.1'] = '10.10.10.1'
TC['20.50.50.2'] = '10.10.10.2'
TC['20.50.50.3'] = '10.10.10.3'
TC['20.50.50.4'] = '10.10.10.4'

############################################
# informacoes armazenadas pelo controlador #
############################################
#CONTROLADOR C2
#cada controlador deve ter o seu
CONTROLADOR_ID = 2
IPC = "10.123.123.2" #IP do root/controlador
MACC = "00:00:00:00:00:06" #MAC do root/controlador
PORTAC_H = 4444 #porta para receber contratos de hosts
PORTAC_C = 8888 #porta para receber contratos de controladores
#dictionary com os ips e as conversoes em ficticios, especifico para cada controlador
IPS_FIC = {}

FILA_C1P1=0
FILA_C1P2=1
FILA_C1P3=2
FILA_C2P1=3
FILA_C2P2=4
FILA_C2P3=5
FILA_BESTEFFORT=6
FILA_CONTROLE=7

#codigos das acoes
CRIAR=0
REMOVER=1

#dicionario para encontrar a rota, em uma situacao real, o controlador sabe quais sao os hosts conectados ao seu dominio, seja pre-configurado ou por aprendizado em packet-in
#LISTA_HOSTS[ip]=switch_dpid
LISTA_HOSTS = {}

arpList = {}
contratos = []
contratos_enviar = {}
#self.mac_to_port = {} arrumar esses dois, tirar do controlador e trzer para ca
#self.ip_to_mac = {}
switches = [] #switches administrados pelo controlador

#vetor com os enderecos ip dos controladores conhecidos (enviaram icmps)
controladores_conhecidos = []

PRE_TABLE = 0 #tabela para lidar com os ips ficticios dos controladores
CLASSIFICATION_TABLE = 1 #tabela para marcacao de pacotes
FORWARD_TABLE = 2 #tabela para encaminhar a porta destino
ALL_TABLES = 255 #codigo para informar que uma acao deve ser tomada em todas as tabelas

CPT = {} #chave (CLASSE,PRIORIDADE,BANDA): valor TOS  
CPF = {} #classe + prioridade = fila
#fila + banda = tos

#banda = valor ; indice = meter_id
#RATES = [4,16,32,64,128,500,1000,2000,4000,8000,10000,20000,25000] #sao 13 meter bands
RATES = [4,32,64,128,500,1000,2000,5000,10000,25000] #novos meters

#alimentar o dicionario CPT !!
#tem que criar uma nova tabela no TCC - tabela TOS
#obs: para acessar o TOS -> CPT[(1,1,'1000')] 
#obs: dscp = int 8 bits

CPT[('1','1','4')] = 0#'000000'
CPT[('1','1','32')] = 1#'000001'
CPT[('1','1','64')] = 2#'000010'
CPT[('1','1','128')] = 3
CPT[('1','1','500')] = 4
CPT[('1','1','1000')] = 5
CPT[('1','1','2000')] = 6
CPT[('1','1','5000')] = 7
CPT[('1','1','10000')] = 8
CPT[('1','1','25000')] = 9

CPT[('1','2','4')] = 10
CPT[('1','2','32')] = 11
CPT[('1','2','64')] = 12
CPT[('1','2','128')] = 13
CPT[('1','2','500')] = 14
CPT[('1','2','1000')] = 15
CPT[('1','2','2000')] = 16
CPT[('1','2','5000')] = 17
CPT[('1','2','10000')] = 18
CPT[('1','2','25000')] = 19

CPT[('1','3','4')] = 20
CPT[('1','3','32')] = 21
CPT[('1','3','64')] = 22
CPT[('1','3','128')] = 23
CPT[('1','3','500')] = 24
CPT[('1','3','1000')] = 25
CPT[('1','3','2000')] = 26
CPT[('1','3','5000')] = 27
CPT[('1','3','10000')] = 28
CPT[('1','3','25000')] = 29

CPT[('2','1','4')] = 30
CPT[('2','1','32')] = 31
CPT[('2','1','64')] = 32
CPT[('2','1','128')] = 33
CPT[('2','1','500')] = 34
CPT[('2','1','1000')] = 35
CPT[('2','1','2000')] = 36
CPT[('2','1','5000')] = 37
CPT[('2','1','10000')] = 38
CPT[('2','1','25000')] = 39

CPT[('2','2','4')] = 40
CPT[('2','2','32')] = 41
CPT[('2','2','64')] = 42
CPT[('2','2','128')] = 43
CPT[('2','2','500')] = 44
CPT[('2','2','1000')] = 45
CPT[('2','2','2000')] = 46
CPT[('2','2','5000')] = 47
CPT[('2','2','10000')] = 48
CPT[('2','2','25000')] = 49

CPT[('2','3','4')] = 50
CPT[('2','3','32')] = 51
CPT[('2','3','64')] = 52
CPT[('2','3','128')] = 53
CPT[('2','3','500')] = 54
CPT[('2','3','1000')] = 55
CPT[('2','3','2000')] = 56
CPT[('2','3','5000')] = 57
CPT[('2','3','10000')] = 58
CPT[('2','3','25000')] = 59

CPT[('3','1','')] = 60 #'111100' #best-effort
CPT[('4','2','1000')] = 61 #'111101' #controle

#CPF - classe + prioridade = fila
CPF[(1,1)] = 0 
CPF[(1,2)] = 1
CPF[(1,3)] = 2
CPF[(2,1)] = 3
CPF[(2,2)] = 4
CPF[(2,3)] = 5
CPF[(3,1)] = 6
CPF[(4,1)] = 7

#BM - banda = meter_id
#MB['']

#servidor para escutar hosts
def servidor_socket_hosts():
    
    #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#um desses funfa
    tcp.bind((IPC, PORTAC_H))
#    tcp.bind(("127.0.1.1", 4444))
#    tcp.bind((socket.gethostbyname(socket.gethostname()),4444))

    #print("host:{0} Ouvindo em {1}".format(socket.gethostname(),socket.gethostbyname(socket.gethostname())))

    tcp.listen(5)

    while True:
        conn, addr = tcp.accept()

        tempo_i = round(time.monotonic()*1000)
        print("[%s] servidor_socket host - recebendo contrato:\n" % (datetime.datetime.now().time()))
        
        #print]("[host]Conectado: ")
        #print](addr)
        #print]("\n")

        data = conn.recv(4)
        qtdBytes = struct.unpack('<i',data)[0]

        data = conn.recv(qtdBytes)
        #print](data)
        contrato = json.loads(data.encode('utf-8'))


        #criar as regras de marcacao e encaminhamento nos switches da entre ip_src e ip_dst
#enviar um icmp 15 ja perguntando se existem controladores interessados em receber o contrato
        #pegar os dados do contrato
        cip_src = contrato['contrato']['ip_origem']
        cip_dst = contrato['contrato']['ip_destino']

        banda = contrato['contrato']['banda']
        prioridade =  contrato['contrato']['prioridade']
        classe =  contrato['contrato']['classe']

        #verificar se ja nao existe um contrato identico - nao recriar
        # no entanto isso nao permite que contratos sejam "renovados"  - deixar quieto
        #for cc in contratos:
        #    if cc['contrato']['ip_origem'] == cip_src and cc['contrato']['ip_destino'] == cip_dst and cc['contrato']['banda'] == banda and cc['contrato']['prioridade'] == prioridade and cc['contrato']['classe'] == classe:
        #        #print]("contrato recebido eh identico a um jah salvo - nada a fazer")
        #        return

#### OBS -- Implementar : garantir que exista apenas um contrato com match para ip_src, ip_dst - e mais campos se forem usar - que se outro contrato vier com esse match, substituir o que ja existe 
#OBS - os contratos sao armazenados como string, entao para acessa-los como json, eh preciso carregar como json: json.loads(contrato)['contrato']['ip_origem']
        #pegar os switches da rota
        switches_rota = SwitchOVS.getRota(str(LISTA_HOSTS[cip_src]), cip_dst)

        #deletando o contrato anterior e as regras a ele associadas
        delContratoERegras(switches_rota, cip_src, cip_dst)

        #print]("contrato salvo \n")
        contratos.append(contrato)      

        print("[%s] servidor_socket host - contrato recebido:\n" % (datetime.datetime.now().time()))
        print(contrato)

        #pegando as acoes do alocarGBAM
        acoes = []

        #em todos os switches da rota - criar regras de encaminhamento
        #nao precisa injetar o pacote,pois era um contrato para este controlador
        for s in switches_rota:
            out_port = s.getPortaSaida(cip_dst)
            acoes_aux = s.alocarGBAM(out_port, cip_src, cip_dst, banda, prioridade, classe)

            #retorno vazio = nao tem espaco para alocar o fluxo
            if len(acoes_aux)==0:
                #rejeitar o fluxo
                #print]("Fluxo rejeitado!\n")
                break
            
            #adicionando as acoes
            for a in acoes_aux:
                acoes.append(a)

        #retorno vazio = nao tem espaco para alocar o fluxo
        if len(acoes_aux)==0:
            #rejeitar o fluxo
            continue

        #chegou ate aqui, entao todos os switches possuem espaco para alocar o fluxo
        #executar cada acao de criar/remover regras\
        #print]("Executar acoes: \n")
        for a in acoes:
            a.executar()
        
        #verificar as regras alocadas
        for s in switches_rota:
            s.listarRegras()

        #1 criar regra de marcacao/classificacao - switch mais da borda = que disparou o packet_in
        #encontrar qual tos foi definido para a criacao da regra no switch de borda mais proximo do emissor
        #pq pegar o tos da regra definida na acao e nao o tos baseado na classe, prioridade e banda do
        # contrato? - pq a regra pode estar emprestando banda, nesse caso, a classe esta diferente da original, e consequentemente o tos tbm esta

        for a in acoes:
            if(a.nome_switch == switches_rota[0].nome and a.codigo == CRIAR):
                #criando a regra de marcacao - switch mais da borda emissora
                switches_rota[0].addRegraC(cip_src, cip_dst, a.regra.tos)
                break

        #enviando o icmp 15 ---- obs nao posso enviar o icmp 15, pois o controlador nao  conhece o end MAC do destino
        # o melhor jeito seria inserir isso no contrato PENSAR
        # como o endereco mac nao importa nesses switches l2 e a ideia eh que o pacote seja aproveitado pelos controladores da rota e nao do host final
        # o host final deve descartar ou ignorar esse pacote
        # assim, eh possivel 'inventar' um endereco MAC e rotear apenas com o endereco IP
        #deve ser enviado pelo switch mais proximo do destino (da borda) - se nao cada switch vai precisar tratar esse pacote
        switch_ultimo = switches_rota[-1]
        switch_ultimo_dp = switch_ultimo.getDP()
        out_port = switch_ultimo.getPortaSaida(cip_dst)

        #print]("Porta SAIDA: %d\n" % (out_port))
        
        #enviar os identificadores do contrato (v2: ip origem/destino sao os identificadores - origem vai em dados, destino vai no destino do icmp ) 
        data = {"ip_src":cip_src}
        data = json.dumps(data)

        send_icmp(switch_ultimo_dp, MACC, TC[IPC], MACC, cip_dst, out_port, 0, data, 1, 15,64)        

        # logging.info('[server-host] fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))        

        #recebeu um contrato fecha a conexao, se o host quiser enviar mais, que inicie outra
        conn.close()
        print("[%s] servidor_socket host - fim:\n" % (datetime.datetime.now().time()))

#servidor para escutar controladores - mesmo que o de hosts, mas o controlador que recebe um contrato nao gera um icmp inf. req.
def servidor_socket_controladores():
    #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#um desses funfa
    tcp.bind((IPC, PORTAC_C))
#    tcp.bind(("127.0.1.1", 4444))
#    tcp.bind((socket.gethostbyname(socket.gethostname()),4444))

    #print]("Controlador:{0} Ouvindo em {1}".format(socket.gethostname(),socket.gethostbyname(socket.gethostname())))

    tcp.listen(5)

    while True:
        conn, addr = tcp.accept()

        print("[%s] servidor_socket controlador - recebendo contrato:\n" % (datetime.datetime.now().time()))
        tempo_i = round(time.monotonic()*1000)
        
        #print]("[controlador]Conectado: ")
        #print](addr)
        #print]("\n")

        #primeiro: receber quantos contratos serao enviados para cah - inteiro de 4 bytes
        data = conn.recv(4)
        qtdContratos = struct.unpack('<i',data)[0]

        #para cada contrato, receber qtd de bytes (outro inteiro de 4 bytes) e entao receber esses bytes
        for i in range(qtdContratos):
            data = conn.recv(4)
            qtdBytes = struct.unpack('<i',data)[0]

            data = conn.recv(qtdBytes)
            #print](data)
            #contrato = json.loads(data.encode('utf-8'))
            #JSON LOADS CARREGA COMO UNICODE essa porcaria
            #contrato = data.decode("utf-8")
            contrato = json.loads(data.encode('utf-8'))

#### OBS -- Implementar : garantir que exista apenas um contrato com match para ip_src, ip_dst - e mais campos se forem usar - que se outro contrato vier com esse match, substituir o que ja existe 
#OBS - os contratos sao armazenados como string, entao para acessa-los como json, eh preciso carregar como json: json.loads(contrato)['contrato']['ip_origem']

                   #criar as regras de marcacao e encaminhamento nos switches da entre ip_src e ip_dst
#enviar um icmp 15 ja perguntando se existem controladores interessados em receber o contrato
        #pegar os dados do contrato
            cip_src = contrato['contrato']['ip_origem']
            cip_dst = contrato['contrato']['ip_destino']

            banda = contrato['contrato']['banda']
            prioridade =  contrato['contrato']['prioridade']
            classe =  contrato['contrato']['classe']

            #pegando os switches da rota
            switches_rota = SwitchOVS.getRota(str(LISTA_HOSTS[cip_src]), cip_dst)

            #deletando o contrato anterior e as regras a ele associadas
            delContratoERegras(switches_rota, cip_src, cip_dst)

            #print]("contrato salvo \n")
            contratos.append(contrato)

            print("[%s] servidor_socket controlador - contrato recebido:\n" % (datetime.datetime.now().time()))
            print(contrato)

            #pegando as acoes do alocarGBAM
            acoes = []

            #em todos os switches da rota - criar regras de encaminhamento
            #nao precisa injetar o pacote,pois era um contrato para este controlador
            for s in switches_rota:
                out_port = s.getPortaSaida(cip_dst)
                acoes_aux = s.alocarGBAM(out_port, cip_src, cip_dst, banda, prioridade, classe)

                #retorno vazio = nao tem espaco para alocar o fluxo
                if len(acoes_aux)==0:
                    #rejeitar o fluxo
                    #print]("Fluxo rejeitado!\n")
                    break

                #adicionando as acoes
                for a in acoes_aux:
                    acoes.append(a)

            #retorno vazio = nao tem espaco para alocar o fluxo
            #
            if len(acoes_aux)==0:
                    #fluxo rejeitado
                continue
            
            #chegou ate aqui, entao todos os switches possuem espaco para alocar o fluxo
            #executar cada acao de criar/remover regras
            for a in acoes:
                a.executar()

            #1 criar regra de marcacao/classificacao - switch mais da borda = que disparou o packet_in
            #encontrar qual tos foi definido para a criacao da regra no switch de borda mais proximo do emissor
            #pq pegar o tos da regra definida na acao e nao o tos baseado na classe, prioridade e banda do
            # contrato? - pq a regra pode estar emprestando banda, nesse caso, a classe esta diferente da original, e consequentemente o tos tbm esta
            
            for a in acoes:
                if(a.nome_switch == switches_rota[0].nome and a.codigo == CRIAR):
                    #criando a regra de marcacao - switch mais da borda emissora
                    switches_rota[0].addRegraC(cip_src, cip_dst, a.regra.tos)
                    break

            #Nao enviar um icmp 15, pois o protocolo atual eh que todos respondam o icmp 15 do primeiro controlador
        #fechar a conexao e aguardar nova
            # logging.info('[server-control] fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))

        conn.close()
        print("[%s] servidor_socket controlador - fim:\n" % (datetime.datetime.now().time()))
    
#remove um contrato e as regras associadas a ele nos switches da rota entre ip_src, ip_dst
def delContratoERegras(switches_rota, cip_src, cip_dst):
    ##checar se ja existe um contrato e remover --- isso ocorre antes de adicionar o novo contrato, por isso consigo pegar o contrato antigo
    for i in contratos:
        if i['contrato']['ip_origem']==cip_src and i['contrato']['ip_destino']==cip_dst:

            #deletar as regras antigas em cada classe switch e no ovs - pegar as informacoes antigas e obter o tos, para entao conseguir remover o contrato/regras antigas
            classe_antiga = i['contrato']['classe']
            prioridade_antiga=i['contrato']['prioridade']
            banda_antiga=i['contrato']['banda']
            tos_antigo = CPT[(classe_antiga, prioridade_antiga, banda_antiga)]
            #print]("[removendo-contrato-antigo] - ip_src:%s; ip_dst:%s; tos:%s\n" % (cip_src, cip_dst,tos_antigo))

            contratos.remove(i)
            for s in switches_rota:
                #deletando na classe switch (de algum dos vetores)
#verificando - o alocar gbam ja remove a regra - ver como ele esta fazendo o del regra e o tos que esta sendo usado - esta usando o tos passado na funcao, ou seja, evita que tenha duas regras iguais
#eh necessario remover aqui a regra que tem os ips iguais mas o tos diferente
                out_port = s.getPortaSaida(cip_dst)
                porta = s.getPorta(out_port)
                #deletando a regra referente ao contrato antigo - pq nao vale mais, ele foi removido
                #se a regra estava ativa, ela sera removida dos switches tbm

                #de qual classe a regra foi removida? classe 1, classe 2, ou -1 regra nao removida
                classe_removida = porta.delRegra(cip_src, cip_dst, tos_antigo)
                #print]("classe removida: %d\n" % (classe_removida))
                if(classe_removida>0):
                    tos_aux = CPT[(str(classe_removida), str(prioridade_antiga), str(banda_antiga))] 
                    #regra ativa
                    s.delRegraT(cip_src, cip_dst, tos_aux, ALL_TABLES)
            
            # aqui fica mais dificil checar se a regra esta ativa - mas eh uma mensagem apenas (aguns pacotes entre controlador e switch de borda)
            # foi alterado novamente para que delRegraT remova a regra em todas as tabelas
            # no primeiro switch remover a regra de marcacao
            #switches_rota[0].delRegraT(cip_src, cip_dst, int(tos_antigo), CLASSIFICATION_TABLE)
            # como nao pode ter mais de um contrato, ja pode retornar
            return

#################
#   INICIANDO SOCKET - RECEBER CONTRATOS (hosts e controladores)
################

t1 = Thread(target=servidor_socket_hosts)
t1.start()

t2 = Thread(target=servidor_socket_controladores)
t2.start()

#t1.join()

def enviar_contratos(host_ip, host_port, ip_dst_contrato):
    #print]("[enviar-contratos] p/ ip_dst: %s, port_dst: %s" %(host_ip, host_port))
    tempo_i = round(time.monotonic()*1000)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((host_ip, host_port))
 
    print("[%s] enviar contrato p/ %s\n" % (datetime.datetime.now().time(), host_ip))

 #teste envio [ok]
#    tcp.connect(("10.123.123.2", host_port))

    contratos_contador = 0
    #contar quantos contratos enviar
    for i in contratos:
        if i['contrato']['ip_destino'] == ip_dst_contrato:
            contratos_contador = contratos_contador+1
            
    #enviar quantos contratos serao enviados
    tcp.send(struct.pack('<i',contratos_contador))

    #para cada contrato, antes de enviar, verificar o size e enviar o size do vetor de bytes a ser enviado
    #encontrar os contratos que se referem ao ip_dst informado e enviar para o host_ip:host_port
    for i in contratos:
        if i['contrato']['ip_destino'] == ip_dst_contrato:
            #print]("enviando->%s" % (json.dumps(i)))
            vetorbytes = json.dumps(i).encode('utf-8')
            qtdBytes = struct.pack('<i',len(vetorbytes))
            tcp.send(qtdBytes)
            tcp.send(vetorbytes)

            print(i)
            #usar send
            # tcp.send(json.dumps(i).encode('utf-8'))

    #fechando a conexao
    #print]("\n")
    tcp.close()
    print("[%s] enviar contrato p/ %s - fim\n" % (datetime.datetime.now().time(), host_ip))
    # logging.info('[Packet_In] icmp 16 - enviar_contrato - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))

############# send_icmp TORNADO GLOBAL EM 06/10 - para ser aproveitado em server socket ###################
#https://ryu-devel.narkive.com/1CxrzoTs/create-icmp-pkt-in-the-controller
#se o ip dest for de um controlador, tem que traduzir o ip para um ficticio para que seja encaminhado pela interface correta, caso contrario esta indo pelo loopback
def send_icmp(datapath, srcMac, srcIp, dstMac, dstIp, outPort, seq, data, id=1, type=8, ttl=64):
    #print]("[send-icmp] type:%d, src:%s, ip_src:%s, dst:%s, ip_dst:%s, psaida %d\n" % (type, srcMac, srcIp, dstMac,dstIp, outPort))

    e = ethernet.ethernet(dst=dstMac, src=srcMac, ethertype=ether.ETH_TYPE_IP)

    iph = ipv4.ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp)

    actions = [datapath.ofproto_parser.OFPActionSetQueue(FILA_CONTROLE), datapath.ofproto_parser.OFPActionOutput(outPort)] #no fim tem que ir na fila de controle

    #se o ip destino for de um controlador, fazer o pacote ser enviado para um ip ficticio e remarcado com o ip correto no switch.
    #se mostrou desnecessario pois eh um pacote injetado, nao originado pela interface do root
    #if dst_controlador == True:
    #    dstIp_traduzido = TC[dstIp]
    #    iph = ipv4.ipv4(4, 5, 0, 0, 0, 2, 0, ttl, 1, 0, srcIp, dstIp_traduzido)
    #    actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_dst=dstIp), datapath.ofproto_parser.OFPActionSetQueue(FILA_CONTROLE), datapath.ofproto_parser.OFPActionOutput(outPort)] #no fim tem que ir na fila de controle

    icmph = icmp.icmp(type, 0, 0, data=data)#pode enviar os dados que quiser, mas tem que ser um vetor binario
        
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(iph)
    p.add_protocol(icmph)
    p.serialize()

    out = datapath.ofproto_parser.OFPPacketOut(
    datapath=datapath,
    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
    in_port=100,
    actions=actions,
    data=p.data)
    #print]("[icmp-enviado]: ")
    #print](out)
    #print]("\n")

    datapath.send_msg(out)
    return 0

def addControladorConhecido(ipnovo):
    #print]("Verificando se ja conhece o controlador: %s \n" %(ipnovo))
    if checkControladorConhecido(ipnovo) == 1:
        #print]("controlador ja conhecido\n")
        return

    controladores_conhecidos.append(ipnovo)
    #print]("novo controlador conhecido\n")

def checkControladorConhecido(ip):
    for i in controladores_conhecidos:
        if i == ip:
            #conhecido
            return 1
    #desconhecido
    return 0

class Regra:
    def __init__(self, ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.porta_dst = porta_dst
        self.tos = tos
        self.emprestando=emprestando
        self.banda = banda
        self.prioridade=prioridade
        self.classe = classe

        #print]("[criando-regra-controlador]src:%s; dst=%s; banda:%s, porta_dst=%d, tos=%s, emprestando=%d" % (self.ip_src, self.ip_dst, self.banda, self.porta_dst, self.tos, self.emprestando)) 

    def toString(self):
        return "[regra]src:%s; dst=%s; banda:%s, porta_dst=%d, tos=%s, emprestando=%d" % (self.ip_src, self.ip_dst, self.banda, self.porta_dst, self.tos, self.emprestando) 

class Porta:
    def __init__(self, name, bandaC1T, bandaC2T, tamanhoFilaC1, tamanhoFilaC2):
        #criar filas e setar quantidade de banda para cada classe

        #tamanhoFila = quanto alem da banda posso alocar/emprestar

        #cada fila deve ter uma variavel de controle de largura de banda utilizada e uma variavel de largura de banda total
        self.nome = name
        #a principio o compartilhamento de largura de banda ocorre apenas entre essas duas classes
        #criar os vetores fila da classe 1
        self.c1T = bandaC1T #banda total para esta classe
        self.c1U = 0 #banda utilizada para esta classe
        #fila baixa prioridade 1, classe 1 (tempo real)
        self.p1c1rules = []
        #fila media prioridade 2, classe 1 (tempo real)
        self.p2c1rules = []
        #fila alta prioridade 3, classe 1 (tempo real)
        self.p3c1rules = []

        #criar os vetores fila da classe 2
        self.c2T = bandaC2T
        self.c2U = 0
        #fila baixa prioridade 1, classe 2 (dados)
        self.p1c2rules = []
        #fila media prioridade 2, classe 2 (dados)
        self.p2c2rules = []
        #fila alta prioridade 3, classe 2 (dados)
        self.p3c2rules = []

        #id do proximo switch (conectado ao link)
        self.next = 0
        #nao eh preciso armazenar informacoes sobre as filas de best-effort e controle de rede

        #O que preciso em cada regra
        #ip_origem
        #ip_destino
        #portalogica_destino?
        #codigo tos (com isso ja sei a largura de banda, a classe e a prioridade)

        #formato das regras json:
        #
        # contrato = {
        #"regra":{
        #    "ip_origem":,
        #    "ip_destino":,
        #    "porta_destino":,
        #    "tos":
        #    }
        #}

    def addRegra(self, ip_src, ip_dst, banda, prioridade, classe, tos, emprestando, porta_dst): #porta = nome da porta
#adicionar regra na fila correta da classe switch no controlador

        if classe == 1:
            self.c1U += int(banda)

            if prioridade == 1:
                self.p1c1rules.append(Regra(ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando))
            elif prioridade ==2:
                self.p2c1rules.append(Regra(ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando))
            else: #prioridade ==3
                self.p3c1rules.append(Regra(ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando))
        else: #classe ==2
            self.c2U += int(banda)

            if prioridade == 1:
                self.p1c2rules.append(Regra(ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando))
            elif prioridade ==2:
                self.p2c2rules.append(Regra(ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando))
            else: #prioridade ==3
                self.p3c2rules.append(Regra(ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando))

        return 0

    
    def delRegra(self, ip_src, ip_dst, tos):
        #retorna 1, caso a regra tenha sido removida na classe 1, e 2 caso tenha sido removida na classe 2
        #print]("[delRegra] porta: %s, src:%s, dst:%s, tos: %d\n" % (self.nome, ip_src, ip_dst, int(tos)))
        #tos eh inteiro no dict
        tos = int(tos)

        #busca e remove a regra seja onde estiver - eh dito que nao deve existir duas regras iguais em nenhum lugar ....
        #regras podem estar na classe original, com uma prioridade, ou emprestando (na outra classe, com a mesma prioridade)

        #acho a tupla chave que representa o valor (tos) -- ou seja, acho a (classe,prioridade,banda)==tos
        keys = [k for k, v in CPT.items() if v == tos]

        #transformar a tupla em lista para poder acessar
        tuplaL = [item for t in keys for item in t] 

        #classe = tuplaL[0]

        prioridade = int(tuplaL[1])
        #banda = [2]

        #como as regras podem emprestar, elas sao armazenadas com o tos original, mas na classe em que emprestam 
        #assim, para cada prioridade, testar as duas classes

        #como pode ter um tos para prioridade 1, e outro tos para prioridade 2, nao posso usar
        
        if prioridade == 1:
            for i in self.p1c1rules:
                if i.ip_src == ip_src and i.ip_dst == ip_dst: #and i.tos == tos:
                    self.c1U -= int(i.banda)
                    self.p1c1rules.remove(i)
                    return 1 #tos da classe 1, prioridade 1

            for i in self.p1c2rules:
                if i.ip_src == ip_src and i.ip_dst == ip_dst: # and i.tos == tos:
                    self.c2U -= int(i.banda)
                    self.p1c2rules.remove(i)
                    return 2 #tos da classe 2, prioridade 1

        elif prioridade == 2:
            for i in self.p2c1rules:
                if i.ip_src == ip_src and i.ip_dst == ip_dst: # and i.tos == tos:
                    self.c1U -= int(i.banda)
                    self.p2c1rules.remove(i)
                    return 1

            for i in self.p2c2rules:
                if i.ip_src == ip_src and i.ip_dst == ip_dst: # and i.tos == tos:
                    self.c2U -= int(i.banda)
                    self.p2c2rules.remove(i)
                    return 2

        else: #prioridade ==3
            for i in self.p3c1rules:
                if i.ip_src == ip_src and i.ip_dst == ip_dst: # and i.tos == tos:
                    self.c1U -= int(i.banda)
                    self.p3c1rules.remove(i)
                    return 1

            for i in self.p3c2rules:
                if i.ip_src == ip_src and i.ip_dst == ip_dst: # and i.tos == tos:
                    self.c2U -= int(i.banda)
                    self.p3c2rules.remove(i)
                    return 2

        #print]("[delRegra]Regra Nao encontrada no switch-controlador\n")
        return -1 #regra nao encontrada

    @staticmethod
    def getRules(porta,classe,prioridade):#dado uma porta, classe, prioridade, retornar o vetor ex: p1c1Rules 
     
        if classe == 1:
            if prioridade == 1:
                return porta.p1c1rules
            elif prioridade ==2:
                return porta.p2c1rules
            else:
                return porta.p3c1rules
        else:
            if prioridade == 1:
                return porta.p1c2rules
            elif prioridade ==2:
                return porta.p2c2rules
            else:
                return porta.p3c2rules


    @staticmethod
    def getUT(porta, classe): #dado uma porta, classe, retornar o Total de banda e a banda utilizada pela classe
        if classe == 1:
            return porta.c1U,porta.c1T
        else:
            return porta.c2U,porta.c2T

class SwitchOVS:
    def __init__(self, datapath, name, qtdPortas, vetNomePortas, bandaC1T, bandaC2T, tamanhoFilaC1, tamanhoFilaC2): 
                
        self.datapath = datapath
        self.nome = name
        self.portas = []

        #isso faz sentido?
        #Como adicionar itens a um dicionario -> dicio['idade'] = 20
        self.macs = {} #chave: mac, valor: porta
        self.redes = {} #chave: ip, valor: porta
        self.hosts= {} #chave: ip, valor: mac

        
        ####### Rotas e saltos
        ####### os vetores/dicionarios anteriores sao suficientes para definir as rotas, no entanto uma maneira mais facil eh com uma tabela especifica orientada para redes (self.redes)
        # em um dominio switches sao programados para possuirem informacoes sobre as rotas que suportam
        # uma informacao de [ip_rede + porta de saida]
        # assim, eh definida uma forma de adicionar e remover informacoes de roteamento, que eh salvo na classe do switch no controlador

        #funcoes necessarias:
        #checkBanda - para ver onde posicionar um fluxo (emprestar largura de banda se preciso)
        #addRegra
        #delRegra - deleta a regra por id
        #getRegra - pensar em um identificador para conseguir as regras
        #updateRegras - passa todas um vetor de regras vindos do switch, para atualizar o vetor da classe

  #criar as portas no switch
        for i in range(qtdPortas):
            self.portas.append(Porta(vetNomePortas[i], bandaC1T, bandaC2T, tamanhoFilaC1, tamanhoFilaC2))

        #print]("\nSwitch %s criado\n" % (name))
    
    @staticmethod
    def getSwitch(nome):

        for i in switches:
            if i.nome == nome:
                return i

        return None

    def updateRegras(self, ip_src, ip_dst, tos):
        #pega todas as regras do switch e atualiza na porta nomePorta (poderia atualizar todas as portas do switch jah)
        
#        Flow Removed Message https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html
#       Quando um fluxo expira ou eh removido no switch, este informa o controlador -- se aproveitar desse evento e atualizar as regras do switch !!!!
        #print]("\n[S%s]UpdateRegras-in\n" % (str(self.nome)))
        #debug
        self.listarRegras()
        #na verdade a del regra esta localizando a classe e prioridade por meio do tos, que seria uma tarefa desta funcao update...
        #obter a porta de saida do switch com a tabela de roteamento com base no ip da rede destino  -- que ainda nao foi implementada
        out_port = self.getPortaSaida(ip_dst)
        porta = self.getPorta(out_port)
        #if(porta.delRegra(ip_src, ip_dst, tos)>0):
        #    print("[updateRegras]regra-removida ip_src:%s, ip_dst:%s, tos:%s\n" % (ip_src,ip_dst,tos))
#
        #print("[S%s]UpdateRegras-ok-out\n" % (str(self.nome)))

        #debug
        self.listarRegras()

        return 0

    def getPorta(self, nomePorta):

        for i in self.portas:
            # %s x %s\n" % (i.nome, nomePorta))
            if str(i.nome) == str(nomePorta):
                return i
        #print("[getPorta] porta inexistente: %s\n" % (nomePorta))
        return None

    def alocarGBAM(self, nomePorta, origem, destino, banda, prioridade, classe):

        banda = int(banda)
        prioridade = int(prioridade)
        classe = int(classe)

        #armazenar as acoes a serem tomadas
        acoes = []

#       As regras sempre estao atualizadas, pois quando uma eh modificada, essa notifica o controlador, que chama updateRegras        
#        self.updateRegras()# atualizar as regras, pois algumas podem nao estar mais ativas = liberou espaco -- implementar

# o TOS eh decidido aqui dentro, pois dependendo do TOS, pode se definir uma banda, uma prioridade e uma classe
#a classe, a prioridade e a banda sao os atributos originais do fluxo

#funcao injetar pacote - o pacote que gera o packet in as vezes, em determinados switches, precisam ser reinjetados
#principalmente no switch que gerou o packet in ou no ultimo switch da rota
#Mas ha casos em que as regras precisam ser criadas nos switches da rota e ser injetado apenas no ultimo, assim, precisa fazer o tratamento

        porta = self.getPorta(str(nomePorta))
 
        print("[alocarGBAM-S%s] porta %s, src: %s, dst: %s, banda: %d, prioridade: %d, classe: %d \n" % (self.nome, str(nomePorta), origem, destino,banda, prioridade, classe))

        #caso seja classe de controle ou best-effort, nao tem BAM, mas precisa criar regras da mesma forma
        #best-effort
        if classe == 3:
            self.addRegraF(origem,destino, 60, nomePorta, 6,None,0, hardtime=10)
            
            return acoes

        #controle
        if classe == 4:
            self.addRegraF(origem,destino, 61, nomePorta, 7,None,0)
            
            return acoes

        #para generalizar o metodo GBAM e nao ter de repetir codigo testando para uma classe e depois para outra
        outraClasse = 1
        if classe == 1:
            outraClasse=2

        #banda usada e total na classe original
        cU, cT = Porta.getUT(porta, classe)

        # print("[antes de alocar] banda usada: %d, banda total: %d \n" % ( cU, cT)) 

        ### antes de alocar o novo fluxo, verificar se ja nao existe uma regra para este fluxo -- caso exista remover e adicionar de novo? ou so nao alocar?
        #a principio - remover e alocar de novo
        tos = CPT[(str(classe), str(prioridade), str(banda))] 
        
        #de qual classe a regra foi removida? classe 1, classe 2, ou -1 regra nao removida
        classe_removida = porta.delRegra(origem, destino, tos)
        if(classe_removida>0):
            tos_aux = CPT[(str(classe_removida), str(prioridade), str(banda))] 
            self.delRegraT(origem, destino, int(tos_aux), ALL_TABLES)
            print("[alocarGBAM]regra removida - ip_src:%s, ip_dst:%s, tos:%s\n" % (origem,destino,tos_aux))
        #pronto, nao vai existir regra duplicada - pode alocar

        #testando na classe original
        if int(banda) <= cT - cU: #Total - usado > banda necessaria
            #criar a regra com o TOS = (banda + classe)
            #regra: origem, destino, TOS ?
            tos = CPT[(str(classe), str(prioridade), str(banda))] #obter do vetor CPT - sei a classe a prioridade e a banda = tos

            #nova acao: criar regra: ip_src: origem, ip_dst: destino, porta de saida: nomePorta, tos: tos, banda:banda, prioridade:prioridade, classe:classe, emprestando: nao
            acoes.append( Acao(self.nome, nomePorta, CRIAR, Regra(origem,destino,nomePorta,tos,banda,prioridade,classe,0)))   

            return acoes #retornando as acoes

        else: #nao ha banda suficiente 
            #verificar se existe fluxo emprestando largura = verificar se alguma regra nas filas da classe esta emprestando banda
            emprestando = []
            bandaE = 0

            #sim: somar os fluxos que estao emprestando e ver se a banda eh suficiente para alocar este fluxo 

            for i in Porta.getRules(porta, classe, 1):
                if i.emprestando == 1:
                    emprestando.append(i)

            for i in Porta.getRules(porta, classe, 2):
                if i.emprestando ==1:
                    emprestando.append(i)

            for i in Porta.getRules(porta, classe, 3):
                if i.emprestando ==1:
                    emprestando.append(i)

            contadorE = 0
            for i in emprestando:
                bandaE += int(i.banda)
                contadorE+=1

                if cT - cU + bandaE >= int(banda):
                    break
            
            #se as regras que estao emprestando representam largura de banda suficiente para que removendo-as, posso alocar o novo fluxo, entao:
            if cT - cU + bandaE >= int(banda):
                for i in range(contadorE): #criando as acoes para remover as regras que estao emprestando
                    acoes.append( Acao(self.nome, nomePorta, REMOVER, Regra(emprestando[i].ip_src,emprestando[i].ip_dst,nomePorta,emprestando[i].tos,emprestando[i].banda,emprestando[i].prioridade,emprestando[i].classe,emprestando[i].emprestando)))   
                
                tos = CPT[(str(classe), str(prioridade), str(banda))] #obter do vetor CPT - sei a classe a prioridade e a banda = tos
                
                #criando a acao  para criar a regra do fluxo, depois de remover as regras selecionadas que emprestam.
                acoes.append( Acao(self.nome, nomePorta, CRIAR, Regra(origem,destino,nomePorta,tos,banda,prioridade,classe,0)))   
                return acoes
                
            else:       #nao: testa o nao
                #nao: ver se na outra classe existe espaco para o fluxo
                #remover os fluxos que foram adicionados em emprestando
                #emprestando.clear()

                #banda usada e total na outra classe
                cOU, cOT = Porta.getUT(porta, outraClasse)
                if int(banda) <= cOT - cOU:

                    #calcular o tos - neste switch o fluxo o tos permanece o mesmo, a regra eh criada no vetor da classe que empresta mas no switch deve ser criada na classe original - isso pode pois todas as filas compartilham da mesma banda e sao limitadas com o controlador
                    tos = CPT[(str(classe), str(prioridade), str(banda))] #novo tos equivalente
                    
                    #sim: alocar este fluxo - emprestando = 1 na classe em que empresta - na fila correspondente
                    acoes.append( Acao(self.nome, nomePorta, CRIAR, Regra(origem,destino,nomePorta,tos,banda,prioridade,outraClasse,1)))   
                    
                    return acoes

                else:
                        #nao: verificar na classe original se nao existem fluxos de menor prioridade que somados dao minha banda
                        
                    bandaP = 0
                    remover = []

                    #sim: remove eles e aloca este
                    if prioridade > 1:
    
                        for i in Porta.getRules(porta, classe, 1):
                            bandaP += int(i.banda)
                            remover.append(i)

                            if cT - cU + bandaP >= int(banda):
                                break
                        
                    if prioridade > 2:
                        if cT - cU + bandaP < int(banda):
                            for i in Porta.getRules(porta, classe, 2):
                                bandaP += int(i.banda)
                                remover.append(i)

                                if cT - cU + bandaP >= int(banda):
                                    break

                    if cT - cU + bandaP >= int(banda):
                        for i in remover:
                            acoes.append( Acao(self.nome, nomePorta, REMOVER, Regra(i.ip_src,i.ip_dst,nomePorta,i.tos,i.banda,i.prioridade,i.classe,i.emprestando)))   
                
                        #adiciona na classe original
                        tos = CPT[(str(classe), str(prioridade), str(banda))] #obter do vetor CPT - sei a classe a prioridade e a banda = tos
                        
                        acoes.append( Acao(self.nome, nomePorta, CRIAR, Regra(origem,destino,nomePorta,tos,banda,prioridade,classe,0)))   
                        
                        return acoes

                    else:

                        #nao: rejeita o fluxo - criando uma regra de drop por uns 5segundos
                        print("[alocaGBMA]fluxo descartado\n")
                        #FAZER NADA - se nao tiver regra, o pacote eh dropado automaticamente.
                        return acoes

        #algum erro ocorreu 
        return acoes


    #criar uma mensagem para remover uma regra de fluxo no ovsswitch
    def delRegraT(self, ip_src, ip_dst, tos, tabela=ALL_TABLES):

        #tabela = 255 = ofproto.OFPTT_ALL = todas as tabelas
        #print("Deletando regra - ipsrc: %s, ipdst: %s, tos: %d, tabela: %d\n" % (ip_src, ip_dst, tos, tabela))
        #tendo o datapath eh possivel criar pacotes de comando para o switch/datapath
        #caso precise simplificar, pode chamar o cmd e fazer tudo via ovs-ofctl

        #modelo com ovs-ofctl:
        #we can remove all or individual flows from the switch
        # sudo ovs-ofctl del-flows <expression>
        # ex. sudo ovs-ofctl del-flows dp0 dl_type=0x800
        # ex. sudo ovs-ofctl del-flows dp0 in_port=1
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #remover a regra meter associada
        meter_id = int(ip_src.split(".")[3] + ip_dst.split(".")[3])                
        self.delRegraM(meter_id)

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_dscp=tos)
        #match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_dst) #, ip_dscp=20)
        #match = parser.OFPMatch()
        #mod = datapath.ofproto_parser.OFPFlowMod(datapath, table_id=tabela, command=ofproto.OFPFC_DELETE,  match=match)
        
        #funcionam
        # mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, match=match)
        # mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, match=match, table_id=ofproto.OFPTT_ALL, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, match=match, table_id=tabela, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

        ##esse funciona - remove tudo
        #mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, table_id=ofproto.OFPTT_ALL, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        
        ##print("deletando regra\n")
        ##print(mod)
        ##print("\n")
        datapath.send_msg(mod)

        return 0

#Injetar pacote no controlador com instrucoes - serve para injetar pacotes que foram encaminhado por packet_in (se nao eles sao perdidos)
    def injetarPacote(self, datapath, fila, out_port, package):
        actions = [datapath.ofproto_parser.OFPActionSetQueue(fila), datapath.ofproto_parser.OFPActionOutput(out_port)] 
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=100,
            actions=actions,
            data=package.data)
        #print("[Pacote-Injetado]: ")
        #print(out)
        #print("\n")

        datapath.send_msg(out)

#add regra tabela FORWARD
    def addRegraF(self, ip_src, ip_dst, ip_dscp, out_port, fila, meter_id, flag, hardtime=None):
        #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
# hardtimeout = 5 segundos # isso eh para evitar problemas com pacotes que sao marcados como best-effort por um contrato nao ter chego a tempo. Assim vou garantir que daqui 5s o controlador possa identifica-lo. PROBLEMA: fluxos geralmente nao duram 5s, mas eh uma abordagem.
        
        #Para que a regra emita um evento de flow removed, ela precisa carregar uma flag, adicionada no OFPFlowMod
        #flags=ofproto.OFPFF_SEND_FLOW_REM
        
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        idletime = 30 # 0 = nao limita
        #hardtime = None

        prioridade = 100
       
        #match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,ipv4_src=ip_src, ipv4_dst=ip_dst,ip_dscp=ip_dscp)
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ip_src, ipv4_dst=ip_dst)
        
        if(ip_dscp != None):
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ip_src, ipv4_dst=ip_dst,ip_dscp=ip_dscp)
        
        actions = [parser.OFPActionSetQueue(fila), parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # essa instrucao eh necessaria?
 
###nao esta funcionando 
        if meter_id != None:
            inst.append(parser.OFPInstructionMeter(meter_id=meter_id))
#            inst = [parser.OFPInstructionMeter(meter_id,ofproto.OFPIT_METER), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        #marcar para gerar o evento FlowRemoved
        if flag == 1:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE, flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)
            return

        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE)

        if hardtime != None:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, hard_timeout = hardtime, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE)

        #print("[addRegraF]:")
        #print(mod)
        #print("\n")

        if(ip_dscp == None):
            ip_dscp = 0
        #printar a regra criada
        #if meter_id != None:
        #    print("[addRegraF-S%s]: src:%s, dst:%s, dscp:%d, porta:%s, fila: %d, meter:%d, flag:%d\n" % (self.nome, ip_src, ip_dst, ip_dscp, out_port, fila, meter_id, flag))
        #else:
        #    print("[addRegraF-S%s]: src:%s, dst:%s, dscp:%d, porta:%s, fila: %d, flag:%d\n" % (self.nome, ip_src, ip_dst, ip_dscp, out_port, fila, flag))

        datapath.send_msg(mod)
        
#add regra tabela CLASSIFICATION
#se o destino for um ip de controlador, 
    def addRegraC(self, ip_src, ip_dst, ip_dscp):
        #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
         #criar regra na tabela de marcacao - obs - utilizar idletime para que a regra suma - serve para que em switches que nao sao de borda essa regra nao exista
                         #obs: cada switch passa por um processo de enviar um packet_in para o controlador quando um fluxo novo chega,assim, com o mecanismo de GBAM, pode ser que pacotes de determinados fluxos sejam marcados com TOS diferentes da classe original, devido ao emprestimo, assim, em cada switch o pacote pode ter uma marcacao - mas com essa regra abaixo, os switches que possuem marcacao diferentes vao manter a regra de remarcacao. Caso ela expire e cheguem novos pacotes, ocorrera novo packet in e o controlador ira executar um novo GBAM - que vai criar uma nova regra de marcacao
        #print("[criando-regra-tabela-marcacao] ipsrc: %s, ipdst: %s, tos: %d\n" % (ip_src, ip_dst, ip_dscp))

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        
#        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP, ipv4_src=ip_src, ipv4_dst=ip_dst)
        
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)
        actions = [parser.OFPActionSetField(ip_dscp=ip_dscp)]

        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        idletime = 30 # 30s sem pacotes, some
        prioridade = 100

        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, priority=prioridade, match=match, instructions=inst, table_id=CLASSIFICATION_TABLE)
        datapath.send_msg(mod)

    #criando regra meter
    def addRegraM(self, meter_id, banda):
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #criando meter bands
        bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=banda, burst_size=10)]#e esse burst_size ajustar?
        req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=bands)
        datapath.send_msg(req)
        return

    def delRegraM(self, meter_id):
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_DELETE, meter_id=meter_id)
        datapath.send_msg(req)
        return

#adicionar rotas no switch - por agora fica com o nome de rede
    def addRede(self, ip_dst, porta): 
        #print("[%s]Rede adicionada %s: %s" % (self.nome, ip_dst, porta))
        self.redes[ip_dst]=porta
        return

    def getPortaSaida(self, ip_dst):
        #retorna int

        if ip_dst in self.redes:
            return self.redes[ip_dst]

        return None

    def delRede(self, ip_dst, porta):
        #print("[%s]Rede deletada %s: %s" % (self.nome, ip_dst, porta))
        return

    def getPortas(self):
        return self.portas
    
    def getDP(self):
        return self.datapath
    
    #dado um conjunto de switches (var global) pertencentes a um dominio/controlador, recuperar o conjunto de switches que fazem parte da rota para o end destino/rede
    @staticmethod
    def getRota(switch_primeiro_dpid, ip_dst):
		#por enquanto nao importam as rotas - rotas fixas e um switch
        #switches eh uma variavel global que compreende os switches do controlador
        #rota = vetor de switches
        rota = []
        ##print("[getRota] src:%s, dst:%s\n" % (ip_src, ip_dst))

        #pegar o primeiro switch da rota, baseado no ip_Src --- ou, por meio do packet in, mas entao nao poderia criar as regras na criacao dos contratos
        switch_primeiro = SwitchOVS.getSwitch(str(switch_primeiro_dpid))
        rota.append(switch_primeiro)

        #pegar o salto do ultimo switch inserido na rota
        nextDpid = switch_primeiro.getPorta(switch_primeiro.getPortaSaida(ip_dst)).next #retorna inteiro

        #print("switch_primeiro: %s, nextDpid: %d\n" % (switch_primeiro.nome, nextDpid))

        while nextDpid > 0:
            s = SwitchOVS.getSwitch(nextDpid)
            rota.append(s)
            #se o .next da porta for -1, esse eh o switch de borda
            nextDpid = s.getPorta(s.getPortaSaida(ip_dst)).next
        
        #for r in rota:
            #print("[rota]: %s" % (r.nome))
            
        return rota

    def listarRegras(self):
        for porta1 in self.getPortas():
            # return
            print("\n[s%s-p%s] listar regras || C1T:%d, C1U:%d || C2T:%d, C2U: %d ||:\n" % (self.nome,porta1.nome, porta1.c1T, porta1.c1U, porta1.c2T, porta1.c2U))
            for rp1c1 in porta1.p1c1rules:
                print(rp1c1.toString()+"\n")
            #print("\n -- C1P2 (qtdregras: %d):" % (este_switch.p2c1rules.length))
            for rp2c1 in porta1.p2c1rules:
                print(rp2c1.toString()+"\n")
            #print("\n -- C1P3 (qtdregras: %d):" % (este_switch.p3c1rules.length))
            for rp3c1 in porta1.p3c1rules:
                print(rp3c1.toString()+"\n")
            #print(" -- C2P1 (qtdregras: %d):" % (este_switch.p1c2rules.length))
            for rp1c2 in porta1.p1c2rules:
                print(rp1c2.toString()+"\n")
            #print("\n -- C2P2 (qtdregras: %d):" % (este_switch.p2c2rules.length))
            for rp2c2 in porta1.p2c2rules:
                print(rp2c2.toString()+"\n")
            #print("\n -- C2P3 (qtdregras: %d):" % (este_switch.p3c2rules.length))
            for rp3c2 in porta1.p3c2rules:
                print(rp3c2.toString()+"\n")


#classe para modelar uma acao - remover ou criar regra
#nome switch - (str) identificar qual switch
#porta - (int) identificar a porta do switch
#codigo - (int) identificar a acao 0-CRIAR, 1-REMOVER
#regra - (Regra) uma regra - com as informacoes suficientes para criar ou remover a regra
class Acao:
    def __init__(self, nome_switch, porta, codigo, regra):
        self.nome_switch=nome_switch
        self.porta = porta
        self.codigo = codigo
        self.regra=regra
    
    def getRegra(self):
        return self.regra
    #regra = [ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando]
    def executar(self):
        print(self.toString())
        if(self.codigo == CRIAR):

            switch = SwitchOVS.getSwitch(self.nome_switch)
            porta = switch.getPorta(self.porta)
            
            #criando a regra no vetor
            porta.addRegra(self.regra.ip_src, self.regra.ip_dst, self.regra.banda, self.regra.prioridade, self.regra.classe, self.regra.tos, self.regra.emprestando, self.regra.porta_dst)
            
            fila = CPF[(self.regra.classe,self.regra.prioridade)] #com o tos obter a fila = classe + prioridade
                
            #criando id unico
            meter_id = int(self.regra.ip_src.split(".")[3] + self.regra.ip_dst.split(".")[3]) #com a banda obter o meter               
            switch.addRegraM(meter_id, int(self.regra.banda))
            print("criando regra meter: meter_id: %d, banda = %s\n" % (meter_id, str(self.regra.banda)))

            #criando a regra na tabela do switch ovs
            # switch.addRegraF(self.regra.ip_src, self.regra.ip_dst, self.regra.tos, self.regra.porta_dst, fila, meter_id, 1)
            switch.addRegraF(self.regra.ip_src, self.regra.ip_dst, self.regra.tos, self.regra.porta_dst, fila, None, 1)
            switch.listarRegras()
        else:

            #codigo == REMOVER
            switch = SwitchOVS.getSwitch(self.nome_switch)
            porta = switch.getPorta(self.porta)
                        
            #removendo a regra no vetor
            porta.delRegra(self.regra.ip_src, self.regra.ip_dst, self.regra.tos)

            #removendo a regra da tabela
            switch.delRegraT(self.regra.ip_src, self.regra.ip_dst, self.regra.tos ,ALL_TABLES) #remove a regra no ovswitch

            switch.delRegraM(meter_id)

            switch.listarRegras()

            #porta.delRegra(emprestando[i].ip_src, emprestando[i].ip_dst, emprestando[i].tos) #remove a regra da classe switch
            #self.delRegraT(emprestando[i].ip_src, emprestando.ip_dst, emprestando[i].tos,FORWARD_TABLE) #remove a regra no ovswitch
        return 0
    
    def toString(self):
        if(self.codigo == REMOVER):
            return "[Acao] Remover: " + self.regra.toString() +"\n"
        return "[Acao] Criar: " + self.regra.toString()+"\n"

class Dinamico(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        #print("CONTROLADOR %s - \n Init Start\n" % (IPC))
        super(Dinamico,self).__init__(*args,**kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

        if CONTROLADOR_ID == 1:
            IPS_FIC['10.10.10.1']='20.10.10.1'
            IPS_FIC['10.10.10.2']='20.10.10.2'
            IPS_FIC['10.10.10.3']='20.10.10.3'
            IPS_FIC['10.10.10.4']='20.10.10.4'
            IPS_FIC['10.10.10.5']='20.10.10.5'
        elif CONTROLADOR_ID == 2:
            IPS_FIC['10.10.10.1']='20.20.20.1'
            IPS_FIC['10.10.10.2']='20.20.20.2'
            IPS_FIC['10.10.10.3']='20.20.20.3'
            IPS_FIC['10.10.10.4']='20.20.20.4'
            IPS_FIC['10.10.10.5']='20.20.20.5'
        elif CONTROLADOR_ID == 3:
            IPS_FIC['10.10.10.1']='20.30.30.1'
            IPS_FIC['10.10.10.2']='20.30.30.2'
            IPS_FIC['10.10.10.3']='20.30.30.3'
            IPS_FIC['10.10.10.4']='20.30.30.4'
            IPS_FIC['10.10.10.5']='20.30.30.5'
        elif CONTROLADOR_ID == 4:
            IPS_FIC['10.10.10.1']='20.40.40.1'
            IPS_FIC['10.10.10.2']='20.40.40.2'
            IPS_FIC['10.10.10.3']='20.40.40.3'
            IPS_FIC['10.10.10.4']='20.40.40.4'
            IPS_FIC['10.10.10.5']='20.40.40.5'
        elif CONTROLADOR_ID == 5:
            IPS_FIC['10.10.10.1']='20.50.50.1'
            IPS_FIC['10.10.10.2']='20.50.50.2'
            IPS_FIC['10.10.10.3']='20.50.50.3'
            IPS_FIC['10.10.10.4']='20.50.50.4'
            IPS_FIC['10.10.10.5']='20.50.50.5'
        else:
            print("ERRO - ID de controlador desconhecido ou nao configurado\nVAI DAR ERRO EM ALGUM LUGAR ADIANTE (nao sera encerrado)\n")


        #print("Init Over\n")

        
        #contrato = {
        #        "contrato":{
        #            "ip_origem":'172.16.10.1',
        #            "ip_destino":'172.16.10.2',
        #            "banda":'1000',
        #            "prioridade":'1',
        #            "classe":'1'
        #    }
        #}

        #contrato = {'contrato':{'ip_origem':'172.16.10.1','ip_destino':'172.16.10.2','banda':'1000','prioridade':'1','classe':'1'}}
        contrato = """{"contrato":{"ip_origem":"172.16.10.1","ip_destino":"172.16.10.2","banda":"1000","prioridade":"1","classe":"1"}}"""
        contratos.append(json.loads(contrato))
        #contratos.append(contrato)

#    def __def__(self):
#        #print("finalizando thread\n")
#        t1.join()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        tempo_i = round(time.monotonic()*1000)
        
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print("[%s] switch_features - setup de S%d \n" % (datetime.datetime.now().time(), datapath.id))

#        switch = ev.switch.dp

        #print("\n[switch_handler] ")

        #print("Switch_id: "+ str(datapath.id) + " conectado: interfaces")
###################################################
###        #criar os switches 
###################################################
   
#        #print("\nEventos possiveis?\n")
#        #print(ofp_event.__dict__)##printar a classe como um dicionario -> identificar os possiveis eventos

        #obter o numero de portas do switch ?
        qtd_portas = 5
        
        nome_portas = []
        for i in range(5):
            nome_portas.append(str(i+1))
        
        #para Total = 15 Mb += 15000kb
        bandaC1T=1000*15 * 0.33 #33%
        bandaC2T=1000*15 * 0.35 #35%

        #para permitir excedente de 10%
        tamanhoFilaC1 = bandaC1T * 0.1 #33 kb
        tamanhoFilaC2 = bandaC2T * 0.1 #35 kb

        switch = SwitchOVS(datapath,str(datapath.id), qtd_portas, nome_portas, bandaC1T, bandaC2T, tamanhoFilaC1, tamanhoFilaC2)
        

        #criando a tabela de roteamento - no momento existem apenas 2 switches
        #em breve serao redes separadas
        #switch S1 - dominio C1 --- arrumado -> porta eh agr um inteiro
        if datapath.id == 1:

            LISTA_HOSTS['10.10.10.1'] = 1
            LISTA_HOSTS['10.123.123.1'] = 1
            LISTA_HOSTS['172.16.10.1'] = 1
            LISTA_HOSTS['172.16.10.2'] = 1
            LISTA_HOSTS['172.16.10.3'] = 1
            LISTA_HOSTS['172.16.10.4'] = 1
            
            switch.addRede('172.16.10.1',1) #rota para destino h1->s1-eth1
            switch.addRede('172.16.10.2',2)
            switch.addRede('172.16.10.3',3)
            switch.addRede('172.16.10.4',4)
            switch.addRede('10.123.123.1',5) #rota para controlador do S1
            switch.addRede('10.123.123.2',4) #rota para controlador do S2
            switch.addRede('10.10.10.2',4) #rota para controlador do S2
            switch.addRede('10.10.10.1',5) #rota para controlador do S1

            # portas ligadas a hosts ou a outros dominios: next = -1; significa que nao podemos pegar switches alem dessa conexao
            switch.getPorta(1).next=-1
            switch.getPorta(2).next=-1
            switch.getPorta(3).next=-1
            #s1:4 <-> s2:1
            switch.getPorta(4).next=-2

            #root1-c1
            switch.getPorta(5).next=-1
		
		
		#switch S2 - dominio C2
        elif datapath.id == 2:

            LISTA_HOSTS['10.10.10.2'] = 2
            LISTA_HOSTS['10.123.123.2'] = 2
            LISTA_HOSTS['172.16.10.4'] = 2
            LISTA_HOSTS['172.16.10.1'] = 2
            LISTA_HOSTS['172.16.10.2'] = 2
            LISTA_HOSTS['172.16.10.3'] = 2
            LISTA_HOSTS['172.16.10.4'] = 2

            switch.addRede('172.16.10.4',1)
            switch.addRede('172.16.10.1',4)
            switch.addRede('172.16.10.2',4)
            switch.addRede('172.16.10.3',4)
            switch.addRede('10.123.123.2',5) #rota para controlador do S2
            switch.addRede('10.123.123.1',4) #rota para controlador do S1
            switch.addRede('10.10.10.2',5) #rota para controlador do S2
            switch.addRede('10.10.10.1',4) #rota para controlador do S1

            # portas ligadas a hosts: next = -1
            switch.getPorta(1).next=-1
            switch.getPorta(4).next=-2
            
            #root2-c2
            switch.getPorta(5).next=-1
   
        switches.append(switch)
        #print("\nSwitch criado\n")

############################################################################################
#####    Criando as regras de rotas entre os switches e o controlador do dominio      ######
##### - os pacotes devem ser enviados pela classe de controle                         ######
##### - Nao precisa de regras de marcacao, pois se o destino eh o                     ######
##### controlador entao automaticamente a classe eh de controle                       ######
##### - criar regra de encaminhamento na rota para o root                             ######
############################################################################################

        global FORWARD_TABLE
        global CLASSIFICATION_TABLE
        global PRE_TABLE

        #regra default da tabela 0 - > enviar para a tabela 1 => caso nao seja pacote com envolvimento nos controladores
        inst = [parser.OFPInstructionGotoTable(CLASSIFICATION_TABLE)]
        # parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=6, ipv4_dst=TC[IPC])
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, instructions=inst, table_id=PRE_TABLE)
        datapath.send_msg(mod)

        #se for o switch que conecta ao controlador, configurar a tabela de pre-marcacao e 
        if datapath.id == 1 or datapath.id == 2 or datapath.id == 3 or datapath.id ==4 or datapath.id ==5:

            ####### TRATAMENTO IPS FICTICIOS ###############
            ### tabela 0 de pre-marcacao, para lidar com os ips ficticios dos controladores

            #pacotes que chegam, do ip-c2 10.10.10.2 devem ser modificados para 20.10.10.2 
            #pacotes que saem com destino ip-c2 20.10.10.2, devem ser modificados para 10.10.10.2
            #alem das conversoes do proprio controlador

            #[mudado, agr cria, nao tem problema e evita um monte de ifs] nao criar regras para si mesmo -- feito da pior forma possivel mas enfim. 
            #comunicacao com os controladores exige traducao de enderecos ficticios
            #10.10.10.2->20.10.10.2

            #ida
            #match:>ip_src, ip_dst; remark:> ip_src, ip_dst
            self.addRegraPre(datapath, IPC, IPS_FIC['10.10.10.1'], TC[IPC], '10.10.10.1')

            #chegada
            #match:>ip_src, ip_dst; remark:> ip_src, ip_dst
            self.addRegraPre(datapath, '10.10.10.1', TC[IPC], IPS_FIC['10.10.10.1'], IPC)

            #ida
            #match:>ip_src, ip_dst; remark:> ip_src, ip_dst
            self.addRegraPre(datapath, IPC, IPS_FIC['10.10.10.2'], TC[IPC], '10.10.10.2')

            #chegada
            #match:>ip_src, ip_dst; remark:> ip_src, ip_dst
            self.addRegraPre(datapath, '10.10.10.2', TC[IPC], IPS_FIC['10.10.10.2'], IPC)

            #10.10.10.3->20.10.10.3
            self.addRegraPre(datapath, IPC, IPS_FIC['10.10.10.3'], TC[IPC], '10.10.10.3')
            #chegada
            #match:>ip_src, ip_dst; remark:> ip_src, ip_dst
            self.addRegraPre(datapath, '10.10.10.3', TC[IPC], IPS_FIC['10.10.10.3'], IPC)

            #10.10.10.4->20.10.10.4
            self.addRegraPre(datapath, IPC, IPS_FIC['10.10.10.4'], TC[IPC], '10.10.10.4')

            #chegada
            #match:>ip_src, ip_dst; remark:> ip_src, ip_dst
            self.addRegraPre(datapath, '10.10.10.4', TC[IPC], IPS_FIC['10.10.10.4'], IPC)

            #10.10.10.5->20.10.10.5
            self.addRegraPre(datapath, IPC, IPS_FIC['10.10.10.5'], TC[IPC], '10.10.10.5')

            #chegada
            #match:>ip_src, ip_dst; remark:> ip_src, ip_dst
            self.addRegraPre(datapath, '10.10.10.5', TC[IPC], IPS_FIC['10.10.10.5'], IPC)

            ###### default para conversar com os 
            #ida
            actions = [parser.OFPActionSetField(ipv4_src=TC[IPC])]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(CLASSIFICATION_TABLE)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=IPC)
            mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst, table_id=PRE_TABLE)
            datapath.send_msg(mod)

            #chegada
            actions = [parser.OFPActionSetField(ipv4_dst=IPC)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(CLASSIFICATION_TABLE)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=TC[IPC])
            mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst, table_id=PRE_TABLE)
            datapath.send_msg(mod)

            ################

            #criar a regra para o controlador do dominio
            #obs: se nao fosse o ultimo switch, que conecta com o controlador, o ip teria de ser o ficticio, mas como eh o ultimo, o ip ficticio eh traduzido antes dessa regra, entao tem que ser o original - assim como esta feito
            actions = [parser.OFPActionSetQueue(FILA_CONTROLE), parser.OFPActionOutput(switch.getPortaSaida(IPC))]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=6, ipv4_dst=IPC)
            mod = parser.OFPFlowMod(datapath=datapath, priority=105, match=match, instructions=inst, table_id=FORWARD_TABLE)
            datapath.send_msg(mod)

        else:
            #nao eh um switch conectado diretamente ao host do controlador (root)
            #tornar a tabela de classificacao a tabela zero

            #criar a regra para o controlador do dominio
            #obs: se nao fosse o ultimo switch, que conecta com o controlador, o ip teria de ser o ficticio, mas como eh o ultimo, o ip ficticio eh traduzido antes dessa regra, entao tem que ser o original - assim como esta feito
            actions = [parser.OFPActionSetQueue(FILA_CONTROLE), parser.OFPActionOutput(switch.getPortaSaida(TC[IPC]))]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=6, ipv4_dst=TC[IPC])
            mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst, table_id=FORWARD_TABLE)
            datapath.send_msg(mod)

#        #print(datapath.address)
#        #print(ev.__dict__)

###########################################################################################
##########        Criar regras TABELAs - marcacao e identificacao              ###########
###########################################################################################
       
		#tabela 0 - classifica os pacotes e envia para a tabela 2
        #criar tabelas https://github.com/knetsolutions/ryu-exercises/blob/master/ex6_multiple_tables.py
        #pacotes sem TOS - sem regras de marcacao e nao sendo icmp information request/reply -> para a tabela 2 (FORWARD)
        
        #[CLASSIFICACAO] regra default -> enviar para tabela 2
        self.add_classification_table(datapath)
       
        #[FORWARD] regra default -> enviar para o controlador
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, FORWARD_TABLE)

        logging.info('[switch_features] fim settage - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))

    	#Regras ICMP inf. Req. e inf. reply --
        
        #as demais regras de marcacao sao feitas com base no packet_in e contratos

    def addRegraPre(self, datapath, ip_src, ip_dst, novo_ip_src, novo_ip_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionSetField(ipv4_src=novo_ip_src), parser.OFPActionSetField(ipv4_dst=novo_ip_dst)]
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_dst, ipv4_src=ip_src)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(CLASSIFICATION_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst, table_id=PRE_TABLE)
        datapath.send_msg(mod)


    def add_flow(self, datapath, priority, match, actions, table_id, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod=None

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,priority=priority, match=match, instructions=inst, table_id=table_id)#, table_id = FORWARD_TABLE)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst, table_id=table_id)#, table_id = FORWARD_TABLE)

        datapath.send_msg(mod)

########### Testando ############

    def add_classification_table(self, datapath):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=CLASSIFICATION_TABLE, instructions=inst, priority=0) #criando a regra default
        datapath.send_msg(mod)

    def add_forward_table(self, datapath, actions, prioridade):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
        mod = None
        if actions == None:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=FORWARD_TABLE,priority=prioridade, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, table_id=FORWARD_TABLE,priority=prioridade, instructions=inst, actions=actions)

        datapath.send_msg(mod)
#
#    def apply_filter_table_rules(self, datapath):
#        ofproto = datapath.ofproto
#        parser = datapath.ofproto_parser
#        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
#        mod = parser.OFPFlowMod(datapath=datapath, table_id=FILTER_TABLE,
#                                priority=10000, match=match)
#        datapath.send_msg(mod)


    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("To dpid {0} packet-out {1}".format(datapath.id, pkt))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    #Quando um fluxo eh removido ou expirou, chama essa funcao. OBJ --> atualizar quais fluxos nao estao mais utilizando banda e remover do switch     
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        #self.logger.debug('OFPFlowRemoved received: '
        #                  'cookie=%d priority=%d reason=%s table_id=%d '
        #                  'duration_sec=%d duration_nsec=%d '
        #                  'idle_timeout=%d hard_timeout=%d '
        #                  'packet_count=%d byte_count=%d match.fields=%s',
        #                  msg.cookie, msg.priority, reason, msg.table_id,
        #                  msg.duration_sec, msg.duration_nsec,
        #                  msg.idle_timeout, msg.hard_timeout,
        #                  msg.packet_count, msg.byte_count, msg.match)
        #print('OFPFlowRemoved received switch=%s :: '
        #                  'cookie=%d priority=%d reason=%s table_id=%d '
        #                  'duration_sec=%d duration_nsec=%d '
        #                  'idle_timeout=%d hard_timeout=%d '
        #                  'packet_count=%d byte_count=%d match.fields=%s \n' % (str(dp.id),
        #                  msg.cookie, msg.priority, reason, msg.table_id,
        #                  msg.duration_sec, msg.duration_nsec,
        #                  msg.idle_timeout, msg.hard_timeout,
        #                  msg.packet_count, msg.byte_count, msg.match))
       
        ip_src = None
        ip_dst = None
        tos = None
        if 'ipv4_dst' in msg.match:
            ip_dst = msg.match['ipv4_dst']
        if 'ipv4_src' in msg.match:
            ip_src = msg.match['ipv4_src']
        if 'ip_dscp' in msg.match:
            tos= msg.match['ip_dscp']
       
        if ip_src == None or ip_dst == None or tos == None:
            #print("Algo deu errado - ip ou tos nao reconhecido\n")
            return 1

        meter_id = int(ip_src.split(".")[3] + ip_dst.split(".")[3])
        #print("[event-flowRemove] ipv4_dst:%s, ipv4_src:%s, ip_dscp:%s\n" % (ip_dst,ip_src,tos))
        print("[%s] flow_removed - removendo regra ip_src: %s, ip_dst: %s, dscp: %d, meter: %d \n" % (datetime.datetime.now().time(), ip_src, ip_dst, int(tos), meter_id))

        #por agora, tanto as regras de ida quanto as de volta sao marcadas para notificar com o evento
        #atualizar no switch que gerou o evento

        switch = SwitchOVS.getSwitch(str(dp.id))
        if switch != None:
            # switch.updateRegras(ip_src, ip_dst, tos) # essa funcao nao faz nada, eh de uma versao antiga --- se tiver tempo, remove-la
            porta_nome = switch.getPortaSaida(ip_dst)
            switch.getPorta(porta_nome).delRegra(ip_src, ip_dst, tos)

            switch.delRegraM(meter_id)

        return 0

    def encontrarMatchContratos(self, ip_src, ip_dst):
        
        #encontrou
        for i in contratos:
            ii = i #json.loads(i)
            cip_src = ii['contrato']['ip_origem']
            cip_dst = ii['contrato']['ip_destino']

            if cip_src == ip_src and cip_dst == ip_dst:
                banda = ii['contrato']['banda']
                prioridade =  ii['contrato']['prioridade']
                classe =  ii['contrato']['classe']
                
                return banda, prioridade, classe


        #nao encontrou
        return None, None, None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        tempo_i = round(time.monotonic()*1000)
        #####           obter todas as informacoes uteis do pacote          #######
        msg = ev.msg #representa a mensagem packet_in
        dp = msg.datapath #representa o switch
        ofp = dp.ofproto #protocolo openflow na versao implementada pelo switch
        parser = dp.ofproto_parser

        #identificar o switch
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        #analisar o pacote recebido usando a biblioteca packet
        pkt = packet.Packet(msg.data)

        #print("[event] Packet_in -- switch: %s\n [Inspecionando pkt]\n" % (str(dpid)))
        #print("Cabecalhos:\n")
        #for p in pkt.protocols:
        #    print (p)

        #obter os cabecalhos https://osrg.github.io/ryu-book/en/html/packet_lib.html
        #obter o frame ethernet
        pkt_eth= pkt.get_protocol (ethernet.ethernet)
        if not pkt_eth:
            return

        ##end macs
        dst = pkt_eth.dst
        src = pkt_eth.src

        #end ips
        ip_src = None
        ip_dst = None

        #tipo pacote
        pkt_type = pkt_eth.ethertype

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            #print("\nPacote IPv4: ")
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst

        print("[%s] pkt_in ip_src: %s; ip_dst: %s\n" % (datetime.datetime.now().time(), ip_src, ip_dst))

        #obter porta de entrada qual o switch recebeu o pacote
        in_port = msg.match['in_port']


        ########        Aprender informacoes no controlador         ################
        #print("\nlistar todos os mac conhecidos")
        #print(self.mac_to_port)

        #print("\nlistar todos os ips conhecidos")
        #print(self.ip_to_mac)

        #print("\nlistar todos os contratos conhecidos\n")

        #for i in contratos:
        #    print(i)

        #print("\nlistar todas as regras do switch-%s:\n" %(str(dpid)))
        este_switch = SwitchOVS.getSwitch(str(dpid))
        este_switch.listarRegras()

        #aprender endereco MAC, evitar flood proxima vez
        self.mac_to_port[dpid][src] = in_port
        #adaptar essa parte depois, aqui so se quer saber se eh conhecida a porta destino para
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = None

        #########             ACOES DO CONTROLADOR              ####################
        #recebi um pacote desconhecido -> Packet_In
        #Sao 2 forks: i)eh Pacote ICMP? ou ii)NAo

        #i) eh Pacote ICMP - verificar se eh ICMP i.1)Information Request ou i.2)information Reply

        #pkt: responder o arp-> request information + continuar com o arp anterior (replicar)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
		
        if pkt_icmp:
            #print("\n Recebeu Pacote ICMP: \n")
            
        ############################3
        ####  RECEBI UM INF. REQUEST:solicitando informacoes - se tem interesse em
        ####  receber o contrato referente ao ip destino (em breve sera adicionado o ip origem tbm):
        #### (i) encapsular o endereco destino do host o qual se quer os contratos em um icmp 16
        #### (2) obter o switch mais proximo do ip_src (controlador que gerou o icmp 15)
        #### (3) enviar o icmp 16 para o ip_src
        #### [suprimido](4) [nao precisa - todos os switches conectados ao controlador possuem 
        # regra de encaminhamento para o controlador estabelecida quando se conectam ao
        #  controlador]criar as regras de marcacao e encaminhamento
        #  de pacotes entre o controlador emissor (ip_src) e o controlador do dominio (IPC)
        # - marcacao no switch mais proximo de ip_src e encaminhamento nos demais switches da rota
        #### (5) encontrar o switch mais proximo do ip_dst (host destino do icmp 15 recebido) e reinjetar o icmp 15 recebido, para descobrir novos controladores
        ############################

            if pkt_icmp.type == 15: #request information -> enviar um information reply
                
                print("[%s] tratamento ICMP 15 \n" % (datetime.datetime.now().time()))

                #aqui se for possivel colocar o endereco destino ao qual o fluxo quer alcancar, nos dados do icmp, sera excelente para identificar os contratos que devem ser enviados. para este controlador
                #enviar um information reply:
                #ip-destino: ip_src -> origem pkt-in
                #mac-destino: src -> origem pkt-in (host root do outro controlador)
                #ip-origem: "10.123.123.1" ip do host root (controlador)
                #mac-origem: "00:00:00:00:00:05" mac do host root
                #output_port: in_port -> do pkt-in

                #preparando o ip destino que desejo os contratos, para solicitar via icmp 16 ao controlador emissor do icmp 15
                #enviando o ip_dst como json
                #print("[ICMP-15] Recebido\n")
                
                addControladorConhecido(ip_src)

                #verificar se ja tenho o contrato e enviar o tos que tenho, caso for o mesmo tos que ja recebi, nao vou receber resposta
                cip_src = json.loads(pkt_icmp.data)['ip_src']
                cip_dst = ip_dst
                dscp = -1
                #procurando  nos contratos o dscp
                for i in contratos:
                    if i['contrato']['ip_origem']==cip_src and i['contrato']['ip_destino']==cip_dst:
                        dscp = CPT[(i['contrato']['classe'], i['contrato']['prioridade'], i['contrato']['banda'])]
                        break

                data = {"ip_dst":ip_dst,"ip_src":cip_src,"dscp":dscp}
                data = json.dumps(data)#.encode()
                #print("[ICMP-15] contrato desejado:%s\n" % (data))  

######### etapa 3 - responder com icmp 16                  
### RESPONDENDO ICMP 15 inf. req com um ICMP 16 inf. reply + ip_dst que quero dos contratos - injetar pelo primeiro switch da rota entre este controlador e o emissor == switch que gerou o packet_in
                ### o primeiro switch da rota eh o proprio que enviou o packet_in
                send_icmp(dp,MACC, TC[IPC], src, ip_src, in_port,0,data,1,16,64) # se mostrou desnecessario, mas deixei a implementacao de qualquer forma, dst_controlador=True)
                #print("[ICMP-15] ICMP Information Request -> Replied\n")

                #as regras de vinda dos pacotes de contrato ja existem, pq sao para este controlador
                #no entanto as regras de volta (tcp-handshake) nao existem e sao do tipo controle tbm, entao criar 
                switches_rota = SwitchOVS.getRota(str(dpid), IPC)
                switches_rota[-1].addRegraC(TC[IPC], ip_src, 61)
                for s in switches_rota:
                    #porta de saida
                    out_port = s.getPortaSaida(ip_src)
                    #ida
                    s.alocarGBAM(out_port, TC[IPC], ip_src, '1000', 2, 4)
######### etapa 4 - suprimida - movida para o switch_feature_handler
            #     #preparar para receber os contratos                
            #     #criar as regras nos switches da rota que leva ao controlador,
            #     # para receber os contratos que serao enviados pelo controlador emissor do inf. req.
            #    #obtendo todos os switches da rota
            #     switches_rota = SwitchOVS.getRota(IPC, ip_src)

            #     #criar a regra de marcacao no switch mais proximo da borda de origem == gerou packet_in
            #     #este_switch = SwitchOVS.getSwitch(str(dpid)) #isso ja foi feito mais acima no codigo
            #     #marcar com tos de controle
            #     este_switch.addRegraC(ip_src, IPC, 29)
                
            #     #em cada switch, o este_switch inclusive, criar as regras de encaminhamento
            #     for s in switches_rota:
            #         out_port = s.getPortaSaida(IPC)
            #         #criando as regras de encaminhamento nos demais switches
            #         s.alocarGBAM(out_port, ip_src, IPC, '1000', '2', '4')

####### etapa 5 - reijetar icmp 15
    ### SEGUINDO O ICMP 15 inf. req. - injetar pelo ultimo switch da  rota
        #obtendo a rota entre src e destino, assim como era antes
                switches_rota = SwitchOVS.getRota(str(dpid), ip_dst)
                
                #obter o switch mais da borda de destino e gerar o inf req para dar sequencia e descobrir novos controladores ate o host destino
                switch_ultimo = switches_rota[-1]
                out_port = switch_ultimo.getPortaSaida(ip_dst)

                switch_ultimo_dp = switch_ultimo.getDP()
                #print("[ICMP-15] Dando sequencia no icmp 15 criando no ultimo switch da rota \n src:%s, dst:%s, saida:%d\n", ip_src, ip_dst, out_port)
                send_icmp(switch_ultimo_dp, src, ip_src, dst, ip_dst,out_port,0,pkt_icmp.data,1,15,64)

                # logging.info('[Packet_In] fim icmp 15  - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
                print("[%s] tratamento ICMP 15 - fim \n" % (datetime.datetime.now().time()))

                return 
                
    ############################3
    #### OUTRO CASO: RECEBI UM INF. REPLY: solicitando que envie os contratos referentes a um determinado host destino
    #### DOIS COMPORTAMENTOS: (i) sou o controlador destino ;; (ii) nao sou o controlador destino
    #### (i): criar as regras na rota entre controlador e destino (switches do dominio)- de marcacao no switch mais proximo do controlador e de encaminhamento nos demais
    #### (ii): criar as regras nos switches entre ip_src e ip_dst para receber os contratos que virao em da direcao ip_dst->ip_src :: - de marcacao no switch mais proxima do controlador destino (ip_dst) - de encaminhamento nos demais
    ############################
            #pkt: responder o arp caso seja para o endereco do controlador-> information reply (enviar os contratos para este controlador)
            if pkt_icmp.type==16:

                #print("[ICMP-16] Recebido\n")
                addControladorConhecido(ip_src)

                ##print("ICMP Information Reply -> Received\n")
                ## somente enviar os contratos caso o controlador seja o destino do icmp, caso contrario, apenas criar as regras de marcacao e encaminhamento + injetar o icmp no switch mais da borda proxima do destino
                switches_rota = SwitchOVS.getRota(str(dpid), ip_src)
                switch_ultimo = switches_rota[-1] ## pegando o ultimo switch da rota
                switch_primeiro = switches_rota[0]

        ###### (i) sou o controlador de destino
                if ip_dst == IPC:
                    
                    print("[%s] tratamento ICMP 16 - controlador destino \n" % (datetime.datetime.now().time()))
                    #enviar os contratos correspondentes para o controlador que respondeu utilizando socket
                    #print("[ICMP-16] Enviar os contratos para: ip_dst %s; mac_dst %s; ip_src e mac_src -> host root\n" % (ip_src,src))

                    dados = json.loads(pkt_icmp.data)
                    cip_src = dados['ip_src']
                    cip_dst = dados['ip_dst']
                    cdscp = dados['dscp']

                    #verificar se o tos recebido no icmp 16 eh o mesmo que o tos do contrato que seria enviado, se for, ignorar esse icmp, o controlador que respondeu ja possui o contrato atualizado
                     #procurando  nos contratos o dscp
                    for i in contratos:
                        if i['contrato']['ip_origem']==cip_src and i['contrato']['ip_destino']==cip_dst:
                            dscp = CPT[(i['contrato']['classe'], i['contrato']['prioridade'], i['contrato']['banda'])]

                            if dscp == cdscp:
                                #print("contrato do controlador solicitante esta atualizado - nao reenviar\n")
                                return
                            #se o contrato foi encontrato e eh diferente, nao precisa testar com os outros contratos
                            break

                    ### criar regras para encaminhar as respostas do ICMP 15 atraves dos switches da rota para o dominio do controlador emissor original e para o controlador enviar os contratos
    #criar regras de marcacao e encaminhamento: switch de borda (switch_ultimo)
    #criar regras de encaminhamento: switches da rota
               
                    #ip_dst = controlador emissor do icmp 15
                    #ip_src = controlador enviando icmp 16
                    #tos = 29 - fila de controle

                    #o ip do host destino final, deve estar nos dados do pacote ICMP = nao implementado ainda
                    #ip_host_destino = msg.data

                    #criar a regra de encaminhamento + marcacao --- para enviar os contratos
                    #regra de marcacao - apenas no switch que esta conectado ao controlador
                    #primeiro switch == switch conectado ao controlador - alterado para TC[ip_src]
                    switch_primeiro.addRegraC(TC[ip_dst], TC[ip_src], 61)

                    #out_port = switch_primeiro.getPortaSaida(ip_src)

                    #criar regras de encaminhamento de contratos nos switches da rota 
                    for s in switches_rota:
                        out_port = s.getPortaSaida(ip_src)
                        s.alocarGBAM(out_port, TC[ip_dst], TC[ip_src], '1000', '2', '4') #criando as regras - alterado para tc[ip_src]

                    #criando a volta tbm pq precisa estabelecer a conexao
                    

                    #enviar_contratos(host_ip, host_port, ip_dst_contrato)
                    # - host_ip e host_port (controlador que envia)
                    # - ip_dst_contrato #ip do host destino (deve estar nos dados do pacote icmp 16 recebido

                    #pegar os dados do pacote - ip_dst
                    #montar o json
                    #filtrar o ip_dst
                    #colocar em enviar contrato
                    #print("[if=16, pkt.data]: ")
                    #print(pkt.__dict__)
                    #print("\n")

                    #estah construindo o json [ok]
                    ##print(json.loads(pkt_icmp.data))
                    #ip_dst desejado para se buscar nos contratos
                    cip_dst = dados['ip_dst']
                    #print("[ICMP-16] enviando contratos do ip_dst desejado - ip_dst:%s\n" % (cip_dst))
                    
                #enviar_contratos(host_ip, host_port, ip_dst_contrato):
                    #ip_src == controlador que enviou o icmp 16
                    #enviar_contratos(ip_src, PORTAC_C, cip_dst)#deve ir pela fila de controle
                    #enviar para um ip ficticio que sera transformado no correto, assim, a interface 
                    #dst_traduzido = TC[ip_src]
                    #traduzir o ip origem (deste controlador), para que se estabeleca a conexao tcp
                    #src_traduzido = TC[ip_dst]
                    #criar a regra de volta para traduzir o ip deste controlador
                    #switch_primeiro.addRegraC(ip_src, dst_traduzido, 61, dst_controlador=True)

                    ##criar regra para na volta remarcar o destino pelo traduzido(reverso)
                    ## ja foi criado a regra para reverter o src na volta, para que mude para o ip deste controlador e ele possa responder

                    #enviar_contratos(ip_src, PORTAC_C, cip_dst)#deve ir pela fila de controle
                    Thread(target=enviar_contratos, args=(ip_src, PORTAC_C, cip_dst,)).start()

                    
                    # logging.info('[Packet_In] icmp 16 - controlador destino - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
                    print("[%s] tratamento ICMP 16 - controlador destino - fim \n" % (datetime.datetime.now().time()))

                    return 0

          ###### (ii) esse controlador nao eh o controlador destino - logo criar as regras de marcacao e encaminhamento para passar os contratos
                #os contratos virao do controlador destino -> controlador origem de icmp 16
                #switches_rota == switches da rota(destino, origem), logo precisa marcar no primeiro switch apenas

                print("[%s] tratamento ICMP 16 - controlador da rota:\n" % (datetime.datetime.now().time()))
                
                switch_primeiro.addRegraC(ip_dst, ip_src, 61)
                
                #print("[ICMP-16] criando regras de encaminhamento de contratos entre src:%s, dst:%s\n" % (ip_dst, ip_src))

                #demais switches: regras de encaminhamento - ida
                for i in switches_rota:
                    out_port = i.getPortaSaida(ip_src) # obtendo a porta que leva a enviar os contratos ao controlador requisitante
                    i.alocarGBAM(out_port,ip_dst, ip_src, '1000', '2', '4') #alocando-criando as regras de encaminhamento

                #criar a volta tbm, pq eh tcp [ultimo switch] e como nao sao pacotes para o controlador desse dominio, nao ha reggras pre-definidas para o encaminhamento
                switches_rota[-1].addRegraC(ip_src, ip_dst, 61)
                for i in switches_rota:
                    out_port = i.getPortaSaida(ip_dst) # obtendo a porta que leva a enviar os contratos ao controlador requisitante
                    i.alocarGBAM(out_port, ip_src, ip_dst, '1000', '2', '4') #alocando-criando as regras de encaminhamento

                #reinjetar o icmp no switch mais da borda proxima do destino
                #print("[ICMP-16] recriando icmp 16 no switch mais proximo src:%s dst:%s out:%s:%d\n" % (ip_src, ip_dst, switch_primeiro.nome, out_port))
                out_port = switch_primeiro.getPortaSaida(ip_dst)
                send_icmp(switch_primeiro.datapath, src, ip_src, dst, ip_dst, out_port, 0,pkt_icmp.data,1,16,64)

                
                # logging.info('[Packet_In] icmp 16 - nao destino - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
                print("[%s]  tratamento ICMP 16 - controlador da rota - fim \n" % (datetime.datetime.now().time()))

                return
        
        #######         Buscar correspondencia Pkt-in com contratos         ############
        #print("---------------------------------\n")
        #print("procurando match com contratos\n")
        if ip_src != None and ip_dst != None:
			
			# (1) identificar se o pacote tem match com algum contrato
            for ii in contratos:
                i = ii#json.loads(i)
                cip_src = i['contrato']['ip_origem']
                cip_dst = i['contrato']['ip_destino']
                 
                if cip_src == ip_src and cip_dst == ip_dst:

                    print("[%s] com match nos contratos :\n" % (datetime.datetime.now().time()))
                    
                    #print("match encontrado\n")

                    #encontramos um match com o contrato i
                    #alocar o fluxo switch conforme seus requisitos - verificar em qual fila o fluxo deve ser posicionado
                    #encontrar todos os switches da rota definida para este ip destino/rede + escolher um switch para enviar o ICMP inf. req. (que deve ser o que disparou o packet_in)
                    switches_rota = SwitchOVS.getRota(str(dpid), ip_dst) #no momento os switches nao estao sendo adicionados em ordem, mas poderiam ser
                    #verificar em qual fila da porta posicionar o fluxo
                    banda = i['contrato']['banda']
                    prioridade =  i['contrato']['prioridade']
                    classe =  i['contrato']['classe']
                    
                    #1- Enviar ICMP inf req. (poderia usar o ultimo switch da rota, mas por agora estamos usando o primeiro, que dispara o packet_in)
                    #ARRUMADO 

                    switches_rota = SwitchOVS.getRota(str(dpid), ip_dst)
                    switch_ultimo = switches_rota[-1]

                    #saber para qual porta deve ser encaminhado --- implementar isso
                    out_port = switch_ultimo.getPortaSaida(ip_dst)
                    switch_ultimo_dp = switch_ultimo.getDP()

                    #teste echo request - se funcionar adaptar para o request information [ok]
                    #deve ser enviado pelo switch mais proximo do destino (da borda) - se nao cada switch vai precisar tratar esse pacote
                    #enviar os identificadores do contrato (v2: ip origem/destino sao os identificadores - origem vai em dados, destino vai no destino do icmp ) 
                    data = {"ip_src":cip_src}
                    data = json.dumps(data)
            
                    send_icmp(switch_ultimo_dp, MACC, TC[IPC], dst, ip_dst, out_port, 0, data, 1, 15,64)
                          
                    #print("[%s] icmp enviado enviado - ipdst=%s  portasaida=%d\n" % (switch_ultimo.nome,ip_dst,out_port))
                    #print("---------------------------------\n")
                             
                    #print("[%s] Criando regra tabela de marcacao no switch de borda (0) - toda regra vinda de outro dominio (borda) deve ser remarcada para valer nesse dominio\n" % (switches_rota[0].nome))
                             
                    #adicionar a regra na classe switch
                    #adicionar a regra na tabela do ovsswitch
                    acoes = []

                    #ANTES VERIFICAR SE A PORTA POSSUI FILA, se nao, nao adianta utilizar GBAM ## no caso todas as portas possuem filas, eu pensava que somente a porta 4 possuia, mas nao eh verdade
                    #### criar as regras em cada switch da rota entre ip_src -> ip_dest
                     #IDA -- em todos os switches da rota
                    for i in range(len(switches_rota)):
                        out_port = switches_rota[i].getPortaSaida(ip_dst)
                        #obtendo o vetor de acoes
                        acoes_aux = switches_rota[i].alocarGBAM(out_port, ip_src, ip_dst, banda, prioridade, classe)

                        #se algum dos switches nao puder alocar, rejeitar o fluxo
                        #retorno vazio = nao tem espaco para alocar o fluxo
                        if len(acoes_aux)==0:
                            #rejeitar o fluxo
                            #print("Fluxo rejeitado!\n")
                            return

                        #adicionando as acoes
                        for a in acoes_aux:
                            acoes.append(a)
                    
                    #chegou ate aqui, entao todos os switches possuem espaco para alocar o fluxo
                    #executar cada acao de criar/remover regras
                    for a in acoes:
                        a.executar()

                    #pegar o switch mais proximo do destino e injetar o pacote que gerou o packet_in
                    out_port = switch_ultimo.getPortaSaida(ip_dst)
                    #a ultima acao deve ser de criar a regra no ultimo switch da rota
                    ultima_acao = acoes[len(acoes)-1]
                    
                    fila = CPF[(ultima_acao.regra.classe, ultima_acao.regra.prioridade)]
                    switch_ultimo.injetarPacote(switch_ultimo.datapath,fila, out_port, msg)

                    #1 criar regra de marcacao/classificacao - switch mais da borda = que disparou o packet_in
                    #encontrar qual tos foi definido para a criacao da regra no switch de borda mais proximo do emissor
                    for a in acoes:
                        if(a.nome_switch == str(dpid) and a.codigo == CRIAR):
                            switches_rota[0].addRegraC(ip_src, ip_dst, a.regra.tos)
                            break
                    

                    # logging.info('[Packet_In] pacote com match - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
                    print("[%s] pkt_in fim \n" % (datetime.datetime.now().time()))
                    return
				
	    #todos os contratos foram checados e nao foi achado correspondencia
            #fluxo nao identificado -> fila de best-effort
            #print("Fluxo nao identificado\n")
            
            print("[%s] sem match nos contratos \n" % (datetime.datetime.now().time()))

            #criar a regra de marcacao para este fluxo com o tos de best effort
            #criar regra para a fila de best-effort (match= {tos, ip_dst} = (meter band + fila=tos) + (porta_saida=ip_dst)
            #1- Encontrar os switches da rota
            switches_rota = SwitchOVS.getRota(str(dpid), ip_dst)
            dscp = 60 #best-effort
            classe = 3 #best-effort

            #se o fluxo for desconhecido (por ter expirado alguma regra) e for de controladores - a classe deve ser classe de controle
            if checkControladorConhecido(ip_src) == 1 or checkControladorConhecido(ip_dst) == 1:
                dscp = 61 #controle
                classe = 4 #controle 

            #criar regra na tabela de classificacao do switch de borda - marcar como best-effort
            #a variavel este switch, pode ser um switch do meio do caminho que perdeu as regras de encaminhamento e gerou o packet_in
            #por isso, deve se usar o primeiro switch da rota para criar as regras, evitando que um switch do meio do caminho tenha regras de marcacao
            #assim, o switch do meio so tem as regras de encaminnhamento atualizadas
            switches_rota[0].addRegraC(ip_src, ip_dst, dscp)    

            for i in range(len(switches_rota)):        
                #criar em cada outro switch as regras de encaminhamento    
                #porta de saida
                out_port = switches_rota[i].getPortaSaida(ip_dst)
                #ida
                switches_rota[i].alocarGBAM(out_port, ip_src, ip_dst, '1000', classe, classe)

            #pegar o switch mais proximo do destino e injetar o pacote que gerou o packet_in
            switch_ultimo = switches_rota[-1]
            out_port = switch_ultimo.getPortaSaida(ip_dst)
            fila = CPF[(classe,1)]
            switch_ultimo.injetarPacote(switch_ultimo.datapath,fila, out_port, msg)

            # logging.info('[Packet_In] pacote sem match - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
            print("[%s] pkt_in fim \n" % (datetime.datetime.now().time()))

            return	 
                    
        
