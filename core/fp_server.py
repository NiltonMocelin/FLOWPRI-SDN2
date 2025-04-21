#avoid circular import https://builtin.com/articles/python-circular-import

import socket
from fp_constants import PORTAC_C, PORTAC_H, PORTAC_X, CRIAR
import pickle
import struct
# from fp_constants import freds

# from fp_switch import Switch

# try:
# from main_controller import delContratoERegras, tratador_regras, send_icmpv4, tratador_addSwitch, tratador_rotas
# except ImportError:
#     print('erro de importacao aa')
    
import json, struct, time, datetime

from fp_utils import tratador_setConfig, tratador_ipsDHCP, tratador_addDominioPrefix

from fp_rota import tratador_addRotas, tratador_delRotas

from fp_openflow_rules import tratador_addRegras, tratador_delRegras

from fp_switch import tratador_delSwitches, tratador_addSwitches
# Criar a configuracao para definir o host de gerenciamento

# Criar a configuracao para resetar as regras -> poder refazer os testes

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


def servidor_configuracoes(controller, ip_server):

    
    print("Iniciando o tratador de arquivos de config....\n")

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #um desses funfa
    tcp.bind((ip_server, PORTAC_X))

    tcp.listen(5)

    while True:
        print("Esperando nova conexao ...")
        conn, addr = tcp.accept()

        data = receive_data(conn)
        
        conn.close()

        print('Recebido de ', addr)
        print('qtd bytes data:',len(data))
        print('json:',data)
        
        cfg = json.loads(data)

        #descobrir qual o tipo de operacao da configuracao
        #realizar as operacoes modificando os switches
        if "addSwitches" in cfg:
            tratador_addSwitches(controller, cfg['addSwitches'])
        
        if "delSwitches" in cfg:
            tratador_delSwitches(controller, cfg['delSwitches'])
            
        if "addRotas" in cfg:
            tratador_addRotas(controller.rotamanager, cfg['addRotas'])
        
        if "delRotas" in cfg:
            tratador_delRotas(controller.rotamanager, cfg['delRotas'])
        
        if "addRegras" in cfg:
            tratador_addRegras(controller, cfg['addRegras'])
        
        if "delRegras" in cfg:
            tratador_delRegras(controller, cfg['delRegras'])
        
        if "setConfig" in cfg:
            tratador_setConfig(controller, cfg['setConfig'])

        if "ipsDHCP" in cfg:
            tratador_ipsDHCP(controller, cfg["ipsDHCP"])

        if "addDominioPrefix" in cfg:
            tratador_addDominioPrefix(controller, cfg["ipsDHCP"])
        print('Configuração realizada')

    return
