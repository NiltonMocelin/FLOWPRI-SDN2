from fp_constants import class_prio_to_queue_id

# from fp_switch import Switch

#para invocar scripts e comandos tc qdisc
import subprocess
import time
import socket

# import main_controller as FL2 
# from main_controller import FLOWPRI2 as FL2

def souDominioBorda(ip_ver:int, ip_src:str, ip_dst:str):
    if check_domain_hosts(ip_src) == True or check_domain_hosts(ip_dst) == True:
        return True
    return False

def check_domain_hosts(ip_src):

    #checar se é ipv4 ou ipv6
    # fazer para iv6 tbm

    meu_ip = get_meu_ip()

    meu_prefix =calculate_network_prefix_ipv4(meu_ip)
    ip_src_prefix = calculate_network_prefix_ipv4(ip_src)

    if meu_prefix == ip_src_prefix:
        return True

    return False

def enviar_msg(msg_str, server_ip, server_port):
    print("Enviando msg_str para -> %s:%s\n" % (server_ip,server_port))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((server_ip, server_port))

    print(msg_str)
    vetorbytes = msg_str.encode("utf-8")
    tcp.send(len(vetorbytes).to_bytes(4, 'big'))
    print(tcp.send(vetorbytes))
    print('len: ', len(vetorbytes))    
    
    tcp.close()
    return 


def calculate_network_prefix_ipv4(ip_v4:str):
    # supomos tudo /24 -> 192.168.1.10 -> 192.168.1.0
    prefix = ip_v4.split(".")

    return prefix[0]+"."+prefix[1]+"."+prefix[2]+".0"

def get_meu_ip():
    return '192.168.0.1'


def send_fred_socket(fred_obj, ip_host_dst, PORTA_HOST_FRED_SERVER):
    print("Enviando fred para -> %s:%s\n" % (ip_host_dst,PORTA_HOST_FRED_SERVER))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((ip_host_dst, PORTA_HOST_FRED_SERVER))

    try:
        # tcp.send(len(dados))
        tcp.send(fred_obj.encode())

        tcp.close()

    except:
        raise SyntaxError("ERRO ao enviar fred !")
    return 

def get_ips_meu_dominio()->list:
    return ["192.168.0.0"] # sei la aqui

def ip_meu_dominio(ip_src):
    """verificar se um host eh meu client"""
    return False


def tratador_addSwitches(addswitch_json,controller):
    """[arrumar] nome dos switches e o id, se comparar como string vai dar ruim, tem que armazenar como inteiro e comparar com inteiro -> pois eles se anunciam como 0000000000000001, as vezes"""

    print("Adicionando configuracao de switch")
    for i in addswitch_json:
        print(i)

        nome_switch = i['nome_switch']

        #procurando o switch
        switch = controller.getSwitchByName(nome_switch)
    
        #encontrar o switch pelo nome
        #criar as portas conforme a configuracao do json
        if(switch == None):
            print("Switch S%s, nao encontrado no dominio - configuracao rejeitada\n" % str(nome_switch))
            continue
        
        # print("mostrando portas \n")
        # print(i['portas'])

        for porta in i['portas']:
            
            print (porta)

            nome_porta = porta['nome_porta']
            largura_porta = porta['banda_total']
            prox_porta = porta['proxSwitch']

            # verificar se porta já existe -> se existir, remover a porta, as regras e as regras OVS
            switch.delPorta(nome_porta)
                
            switch.addPorta(nome_porta, int(largura_porta), int(prox_porta))

            interface = "s" + str(nome_switch) + "-eth"+ str(nome_porta)
###
            #criar as novas filas
            lbandatotal = int(largura_porta)
            #classe tempo-real ids=[0,1,2]
            lbandaclasse1 = int(lbandatotal * 0.33)
            #classe nao-tempo-real/dados ids=[3,4,5]
            lbandaclasse2 = int(lbandatotal * 0.35)
            #classe best-effort id = 6
            lbandaclasse3 = int(lbandatotal * 0.25)
            #classe controle id = 7
            lbandaclasse4 = int(lbandatotal * 0.07)

            #obs desse jeito so funciona em rede local!!! --- se o switch estiver em outro pc nao rola -- tem que utilizar a conexao com ovsdb sei la
            p = subprocess.Popen("echo mininet | sudo ovs-vsctl clear port {} qos".format(interface), stdout=subprocess.PIPE, shell=True)

            print("[new_switch_handler]Entradas de qos anteriores foram removidas do ovsdb para a porta {}".format(nome_porta))

            p = subprocess.Popen("echo mininet | sudo -S tc qdisc del dev {} root".format(interface), stdout=subprocess.PIPE, shell=True)

            # print(p.__dict__)
            if(p.stderr == None):
                print("[new_switch_handler] SUCESSO - filas anteriores removidas {}".format(interface))
            else:
                print("[new_switch_handler] FALHA - Erro em remover filas anteriores {}".format(interface))

            #tentar com apenas a configuracao ovs-vsctl - sem limpar o tcqdisc ---> nao funciona
            #ovs-vsctl clear port s1-eth4 qos

            # # queues = [{'min-rate': '10000', 'max-rate': '100000', 'priority': '5'},{'min-rate':'500000'}]
            # # ovs_bridge.set_qos(interface, type='linux-htb', max_rate="15000000", queues=queues)
            # # #deu certo?

            script_qos = "echo mininet | sudo ovs-vsctl -- set port {} qos=@newqos -- \
                                    --id=@newqos create qos type=linux-htb other-config:max-rate={} \
                                    queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- \
                                    --id=@q0 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q1 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=5 -- \
                                    --id=@q2 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 -- \
                                    --id=@q3 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q4 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=5 -- \
                                    --id=@q5 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 -- \
                                    --id=@q6 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
                                    --id=@q7 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 \
                                    ".format(interface, 
                                    str(lbandatotal),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
                                    str(lbandaclasse3), str(lbandatotal),
                                    str(lbandaclasse4), str(lbandaclasse4+100))

            print(script_qos)                                    
            #aplicando o script aqui
            p = subprocess.Popen(script_qos, stdout=subprocess.PIPE, shell=True)

            if(p.stderr == None):
                print("[new_switch_handler] SUCESSO - Novas configuracoes de filas foram estabelecidas porta {}\n{}".format(interface,script_qos))
            else:
                print("[new_switch_handler] FALHA - Erro em novas configuracoes de filas porta {}\n{}".format(interface,script_qos))
 
def tratador_delSwitches(switch_cfg, controller):

    nome_switch = switch_cfg['nome_switch']
    #encontrar o switch
    switch_obj = controller.getSwitchByName(nome_switch)

    if switch_obj == None:
        return
    
    for porta in switch_obj.getPortas():
        switch_obj.delPorta(porta.nome)

    controller.switches.remove(switch_obj)

    print('Switch removido: %s' % (nome_switch))


def tratador_addRegras(novasregras_json, controller):
    #   *Nao implementado*
    # -> encontrar o switch onde as regras devem ser instaladas
    # tipos de regras possiveis
    # - delete e add
    # - regras marcacao
    # - regras meter (classes com qos -> gbam)
    # - regra de encaminhamento (best-effort)

    for regra in novasregras_json:

        print(regra)

        nome_switch = regra['nome_switch']
        switch_obj = None
        
        #encontrar o switch
        switch_obj = controller.getSwitchByName(nome_switch)
        
        if switch_obj == None:
            print("Regra falhou!!")
            #tentar a proxima regra
            continue

        ip_ver = regra['ip_ver']
        ip_src = regra['ip_src']
        ip_dst = regra['ip_dst']
        porta_saida = regra['porta_saida']
        src_port = regra['src_port']
        dst_port = regra['dst_port']
        proto = regra['proto']
        #isso vai ser modificado outro momento
        classe = regra['classe']
        prioridade = regra['prioridade']
        banda = regra['banda']

        switch_obj.alocarGBAM(ip_ver=ip_ver, ip_src = ip_src, ip_dst = ip_dst, proto=proto, dst_port = dst_port, src_port= src_port, porta_saida = porta_saida, banda=banda, prioridade=prioridade, classe=classe)

    return None

def tratador_delRegras(regras_json, controller):

    for regra in regras_json:

        nome_switch = regras_json['nome_switch']
        switch_obj = None
    
        #encontrar o switch
        switch_obj = controller.getSwitchByName(nome_switch)
        
        if switch_obj == None:
            print("Regra falhou!!")
            #tentar a proxima regra
            continue

        ip_ver = regra['ip_ver']
        ip_src = regra['ip_src']
        ip_dst = regra['ip_dst']
        src_port = regra['src_port']
        dst_port = regra['dst_port']
        proto = regra['proto']
        #isso vai ser modificado outro momento
        classe = regra['classe']
        prioridade = regra['prioridade']
        banda = regra['banda']
        porta_saida = regra['porta_saida']

        if not switch_obj.delRegraGBAM(ip_ver=ip_ver, ip_src = ip_src, ip_dst = ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, porta_saida = porta_saida, banda=banda, prioridade=prioridade, classe=classe):
                #se for uma regra best-effort remover aqui
                switch_obj.delRegraT(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst,src_port=src_port, dst_port=dst_port, proto=proto,ip_dscp=None)

    return

def get_eth_header(eth_pkt):
    if eth_pkt:
        return eth_pkt.dst,eth_pkt.src,eth_pkt.ethertype
    return None, None, None

def get_ipv4_header(ipv4_pkt):
    if ipv4_pkt:
        return ipv4_pkt.version,ipv4_pkt.header_length,ipv4_pkt.tos,ipv4_pkt.total_length,ipv4_pkt.identification,ipv4_pkt.flags,ipv4_pkt.offset,ipv4_pkt.ttl,ipv4_pkt.proto,ipv4_pkt.csum,ipv4_pkt.src,ipv4_pkt.dst,ipv4_pkt.option
    return None,None,None,None,None,None,None,None,None,None,None,None,None

def get_ipv6_header(ipv6_pkt):
    if ipv6_pkt:
        return ipv6_pkt.version,ipv6_pkt.traffic_class,ipv6_pkt.flow_label,ipv6_pkt.payload_length,ipv6_pkt.nxt,ipv6_pkt.hop_limit,ipv6_pkt.src,ipv6_pkt.dst,ipv6_pkt.ext_hdrs
    return None,None,None,None,None,None,None,None,None

def get_tcp_header(tcp_pkt):
    if tcp_pkt:
        return tcp_pkt.src_port,tcp_pkt.dst_port,tcp_pkt.seq,tcp_pkt.ack,tcp_pkt.offset,tcp_pkt.bits,tcp_pkt.window_size,tcp_pkt.csum,tcp_pkt.urgent,tcp_pkt.option
    return None,None,None,None,None,None,None,None,None,None

def get_udp_header(udp_pkt):
    if udp_pkt:
        return udp_pkt.src_port,udp_pkt.dst_port,udp_pkt.total_length,udp_pkt.csum
    return None,None,None,None


def addControladorConhecido(ipnovo:str, controller):
    #print]("Verificando se ja conhece o controlador: %s \n" %(ipnovo))
    if checkControladorConhecido(ipnovo) == 1:
        #print]("controlador ja conhecido\n")
        return

    controller.controladores_conhecidos.append(ipnovo)
    #print]("novo controlador conhecido\n")

def checkControladorConhecido(ip:str, controller):
    for i in controller.controladores_conhecidos:
        if i == ip:
            #conhecido
            return 1
    #desconhecido
    return 0  

def remover_freds_expirados(switch):
    return
    
def current_milli_time():
    return round(time.time() * 1000)


def getQueueId(classe, prioridade):
    return class_prio_to_queue_id[classe*10+prioridade]


def getEquivalentMonitoringMark(qos_mark):
    return qos_mark+2

def getQoSMark(classe:int, prio:int):
    return getQueueId(classe, prio) + 1

def getQOSMark(classe:int, prioridade:int):
    return classe*10+prioridade