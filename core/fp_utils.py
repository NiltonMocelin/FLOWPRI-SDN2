# from main_controller import FLOWPRI2
from fp_constants import class_prio_to_queue_id, class_prio_to_monitoring_mark

#para invocar scripts e comandos tc qdisc
import subprocess
import time
import socket
import pickle
import struct

from ryu.lib.ovs import vsctl
from ryu.lib.ovs.bridge import OVSBridge

# def check_domain_hosts(ip_src, meu_ip):

#     #checar se é ipv4 ou ipv6
#     # fazer para iv6 tbm
#     meu_prefix =calculate_network_prefix_ipv4(meu_ip)
#     ip_src_prefix = calculate_network_prefix_ipv4(ip_src)

#     if meu_prefix == ip_src_prefix:
#         return True

#     return False

# def souDominioBorda(ip_ver:int, ip_src:str, ip_dst:str):
#     if check_domain_hosts(ip_src) == True or check_domain_hosts(ip_dst) == True:
#         return True
#     return False


def send_data(conn, data):
    serialized_data = pickle.dumps(data)
    conn.sendall(struct.pack('>I', len(serialized_data)))
    conn.sendall(serialized_data)


def receive_data(conn):
    data_size = struct.unpack('>I', conn.recv(4))[0]
    received_payload = b""
    reamining_payload_size = data_size
    while reamining_payload_size != 0:
        received_payload += conn.recv(reamining_payload_size)
        reamining_payload_size = data_size - len(received_payload)
    data = pickle.loads(received_payload)

    return data


def enviar_msg(msg_str, server_ip, server_port):
    print("Enviando msg_str para -> %s:%s\n" % (server_ip,server_port))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((server_ip, server_port))

    send_data(tcp, msg_str)
    
    tcp.close()
    return 


def calculate_network_prefix_ipv4(ip_v4:str):
    # supomos tudo /24 -> 192.168.1.10 -> 192.168.1.0
    print('calculate_prefix de: ', ip_v4)
    prefix = ip_v4.split(".")

    return prefix[0]+"."+prefix[1]+"."+prefix[2]+".0"


def send_fred_socket(fred_obj, ip_host_dst, PORTA_HOST_FRED_SERVER):
    print("Enviando fred para -> %s:%s\n" % (ip_host_dst,PORTA_HOST_FRED_SERVER))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((ip_host_dst, PORTA_HOST_FRED_SERVER))

    try:
        # tcp.send(len(dados))
        send_data(tcp, fred_obj)
        # tcp.send(fred_obj.encode())

        tcp.close()

    except:
        raise SyntaxError("ERRO ao enviar fred !")
    return 



def tratador_setConfig(controller, switch_cfg):
    """{"setConfig":{"nome_config":"ManagementSwitch","valor":"ipswitch"}}"""
    if switch_cfg['nome_config'] == 'ManagementSwitch':
        ip_switch = switch_cfg['valor']
        controller.ip_management_host = ip_switch

def tratador_ipsDHCP(controller, _cfg):
    """"ipsDHCP":[{"ip":"172.16.0.1"},{"ip":"172.16.0.2"},{"ip":"172.16.0.3"},{"ip":"172.16.0.4"},{"ip":"172.16.0.5"}]"""
    for prefix in _cfg:
        controller._LIST_IPS_DHCP.append(prefix["ip"])
    return

def tratador_addDominioPrefix(controller, _cfg):
    """"addDominioPrefix":[{"ip":"172.16.0.0"}]"""
    for prefix in _cfg:
        controller._LIST_PREFIX_DOMINIO.append(prefix["ip"])
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


def addControladorConhecido(controller, ipnovo:str):
    #print]("Verificando se ja conhece o controlador: %s \n" %(ipnovo))
    if checkControladorConhecido(ipnovo) == 1:
        #print]("controlador ja conhecido\n")
        return

    controller.controladores_conhecidos.append(ipnovo)
    #print]("novo controlador conhecido\n")

def checkControladorConhecido(controller, ip:str):
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


def getEquivalentMonitoringMark(classe, prioridade):
    return class_prio_to_monitoring_mark[classe*10+prioridade]

# def getQoSMark(classe:int, prio:int):
#     return getQueueId(classe, prio) + 1

def getQOSMark(classe:int, prioridade:int):
    return classe*10+prioridade


def prepare_htb_queues_switch(controller, switch):
    """api do protocolo ovs-vsctl está com erros, se usar um server próprio pode rola, mas vou usar scripts pela agilidade necessária nessa etapa"""
    # switch_ovsdb_addr = 'tcp:127.0.0.1:6653'
    # if switch_ovsdb_addr == '':
    #     print("[htb-cfg] error:s%d -> ovsdb_addr not set = skip"%(switch.nome))


    # # # tentar usar esse set_qos(port_name, type='linux-htb', max_rate=None, queues=None) ou abandonar e ir apenas por script mesmo...
    # ovsb = OVSBridge(controller.CONF, switch.datapath.id, switch_ovsdb_addr)

    for port in switch.getPortas():
        print("nome-switch: %d porta: %d  interface: %s" % (switch.nome,port.nome, port.interface_name))

        # params = {"port_name": "s%d-eth%d"%(switch.nome, port.nome), "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"min_rate": "800000"}]}

        # ovsb.set_qos(port_name='s%s-eth%d'%(switch.nome, port.nome), type='linux-htb', max_rate="1000000", queues=None)

        # ovsb.set_qos(port_name="s%d-eth%d"%(port.nome), type='linux-htb', max_rate="1000000", queues=None)
        #limpar qos
        # config = 'clear', ('port', 's%s-eth%d qos'%(switch.nome,port.nome))
        # sendConfigOVS(ovsdb_addr=switch_ovsdb_addr, config=config)

        # config = ('set', ('port', 's%s-eth%d@if2'%(switch.nome,port.nome), 'qos=@newqos --' , '--id=@newqos create qos type=linux-htb other-config:max-rate=%d'%(port.bandaT),
        #                 'queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 --',
        #                 '--id=@q0 create queue other-config:min-rate=%d other-config:max-rate=%d other-config:priority=10 --' %(port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal, port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal+100),
        #                 '--id=@q1 create queue other-config:min-rate=%d other-config:max-rate=%d other-config:priority=5 --'  %(port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal, port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal+100) ,
        #                 '--id=@q2 create queue other-config:min-rate=%d other-config:max-rate=%d other-config:priority=2 --'  %(port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal, port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal+100) ,
        #                 '--id=@q3 create queue other-config:min-rate=%d other-config:max-rate=%d other-config:priority=10 --' %(port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal, port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal+100),
        #                 '--id=@q4 create queue other-config:min-rate=%d other-config:max-rate=%d other-config:priority=5 --'  %(port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal, port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal+100) ,
        #                 '--id=@q5 create queue other-config:min-rate=%d other-config:max-rate=%d other-config:priority=2 --'  %(port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal, port.bandaTotalClasseReal+port.bandaTotalClasseNaoReal+100) ,
        #                 '--id=@q6 create queue other-config:min-rate=%d other-config:max-rate=%d other-config:priority=10 --' %(port.bandaTotalClasseBE, port.bandaTotal),
        #                 '--id=@q7 create queue other-config:min-rate=%d other-config:max-rate=%d other-config:priority=2'     %(port.bandaTotalClasseControle, port.bandaTotalClasseControle+100)))
        # sendConfigOVS(ovsdb_addr=switch_ovsdb_addr, config=config)

        # interface = "s%d-eth%d" % (switch.nome,port.nome)
        interface = port.interface_name

        largura_porta= port.bandaT # 500 000 == 500kb

    # precisa ter esse formato...
    # {"port_name": "eth2", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"min_rate": "800000"}]}'
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
        p = subprocess.Popen("echo 214336414 | sudo -S ovs-vsctl clear port {} qos".format(interface), stdout=subprocess.PIPE, shell=True)

        print("[new_switch_handler]Entradas de qos anteriores foram removidas do ovsdb para a porta {}".format(interface))

        # p = subprocess.Popen("echo 214336414 | sudo -S tc qdisc del dev {} root".format(interface), stdout=subprocess.PIPE, shell=True)

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

        script_qos = "echo 214336414 | sudo -S ovs-vsctl -- set port {} qos=@newqos -- \
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

        # print(script_qos)                                    
        #aplicando o script aqui
        p = subprocess.Popen(script_qos, stdout=subprocess.PIPE, shell=True)

        if(p.stderr == None):
            print("[new_switch_handler] SUCESSO - Novas configuracoes de filas foram estabelecidas porta {}\n{}".format(interface,script_qos))
        else:
            print("[new_switch_handler] FALHA - Erro em novas configuracoes de filas porta {}\n{}".format(interface,script_qos))
 
    
    return


def sendConfigOVS(ovsdb_addr, config):
    """ip do switch e porta == tcp:127.0.0.1:6640"""
    OVSDB_ADDR = ovsdb_addr
    ovs_vsctl = vsctl.VSCtl(OVSDB_ADDR)
    command = vsctl.VSCtlCommand(config)

    # $ ovs-vsctl list Port s1-eth1
    # Equivalent to command = vsctl.VSCtlCommand('list', ('Port', 's1-eth1'))
    command = vsctl.VSCtlCommand('show')
    ovs_vsctl.run_command([command])

    ovs_vsctl.run_command([command])
    print(command.result[0].name)





################### ESSE FUNCIONAVE == BACKUP
# def tratador_addSwitches(controller, addswitch_json):
#     """[arrumar] nome dos switches e o id, se comparar como string vai dar ruim, tem que armazenar como inteiro e comparar com inteiro -> pois eles se anunciam como 0000000000000001, as vezes"""

#     print("Adicionando configuracao de switch")
#     for i in addswitch_json:
#         print(i)

#         nome_switch = i['nome_switch']

#         #procurando o switch
#         switch = controller.getSwitchByName(nome_switch)
    
#         #encontrar o switch pelo nome
#         #criar as portas conforme a configuracao do json
#         if(switch == None):
#             print("Switch S%s, nao encontrado no dominio - configuracao rejeitada\n" % str(nome_switch))
#             continue
        
#         # print("mostrando portas \n")
#         # print(i['portas'])

#         for porta in i['portas']:
            
#             print (porta)

#             nome_porta = porta['nome_porta']
#             largura_porta = porta['banda_total']
#             prox_porta = porta['proxSwitch']

#             # verificar se porta já existe -> se existir, remover a porta, as regras e as regras OVS
#             switch.delPorta(nome_porta)
                
#             switch.addPorta(nome_porta, int(largura_porta), int(prox_porta))

#             interface = "s" + str(nome_switch) + "-eth"+ str(nome_porta)
# ###
#             #criar as novas filas
#             lbandatotal = int(largura_porta)
#             #classe tempo-real ids=[0,1,2]
#             lbandaclasse1 = int(lbandatotal * 0.33)
#             #classe nao-tempo-real/dados ids=[3,4,5]
#             lbandaclasse2 = int(lbandatotal * 0.35)
#             #classe best-effort id = 6
#             lbandaclasse3 = int(lbandatotal * 0.25)
#             #classe controle id = 7
#             lbandaclasse4 = int(lbandatotal * 0.07)

#             #obs desse jeito so funciona em rede local!!! --- se o switch estiver em outro pc nao rola -- tem que utilizar a conexao com ovsdb sei la
#             p = subprocess.Popen("echo mininet | sudo ovs-vsctl clear port {} qos".format(interface), stdout=subprocess.PIPE, shell=True)

#             print("[new_switch_handler]Entradas de qos anteriores foram removidas do ovsdb para a porta {}".format(nome_porta))

#             p = subprocess.Popen("echo mininet | sudo -S tc qdisc del dev {} root".format(interface), stdout=subprocess.PIPE, shell=True)

#             # print(p.__dict__)
#             if(p.stderr == None):
#                 print("[new_switch_handler] SUCESSO - filas anteriores removidas {}".format(interface))
#             else:
#                 print("[new_switch_handler] FALHA - Erro em remover filas anteriores {}".format(interface))

#             #tentar com apenas a configuracao ovs-vsctl - sem limpar o tcqdisc ---> nao funciona
#             #ovs-vsctl clear port s1-eth4 qos

#             # # queues = [{'min-rate': '10000', 'max-rate': '100000', 'priority': '5'},{'min-rate':'500000'}]
#             # # ovs_bridge.set_qos(interface, type='linux-htb', max_rate="15000000", queues=queues)
#             # # #deu certo?

#             script_qos = "echo mininet | sudo ovs-vsctl -- set port {} qos=@newqos -- \
#                                     --id=@newqos create qos type=linux-htb other-config:max-rate={} \
#                                     queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- \
#                                     --id=@q0 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
#                                     --id=@q1 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=5 -- \
#                                     --id=@q2 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 -- \
#                                     --id=@q3 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
#                                     --id=@q4 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=5 -- \
#                                     --id=@q5 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 -- \
#                                     --id=@q6 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=10 -- \
#                                     --id=@q7 create queue other-config:min-rate={} other-config:max-rate={} other-config:priority=2 \
#                                     ".format(interface, 
#                                     str(lbandatotal),
#                                     str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
#                                     str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
#                                     str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
#                                     str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
#                                     str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
#                                     str(lbandaclasse1+lbandaclasse2), str(lbandaclasse1+lbandaclasse2+100),
#                                     str(lbandaclasse3), str(lbandatotal),
#                                     str(lbandaclasse4), str(lbandaclasse4+100))

#             print(script_qos)                                    
#             #aplicando o script aqui
#             p = subprocess.Popen(script_qos, stdout=subprocess.PIPE, shell=True)

#             if(p.stderr == None):
#                 print("[new_switch_handler] SUCESSO - Novas configuracoes de filas foram estabelecidas porta {}\n{}".format(interface,script_qos))
#             else:
#                 print("[new_switch_handler] FALHA - Erro em novas configuracoes de filas porta {}\n{}".format(interface,script_qos))
 