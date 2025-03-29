#avoid circular import https://builtin.com/articles/python-circular-import

import socket
from fp_constants import PORTAC_C, PORTAC_H, PORTAC_X, CRIAR
# from fp_constants import freds

# from fp_switch import Switch

# try:
# from main_controller import delContratoERegras, tratador_regras, send_icmpv4, tratador_addSwitch, tratador_rotas
# except ImportError:
#     print('erro de importacao aa')
    
import json, struct, time, datetime

from fp_utils import tratador_addSwitches, tratador_delSwitches

from fp_rota import tratador_addRotas, tratador_delRotas

from fp_openflow_rules import tratador_addRegras, tratador_delRegras

# Criar a configuracao para definir o host de gerenciamento

# Criar a configuracao para resetar as regras -> poder refazer os testes

def servidor_configuracoes(controller, ip_server):

    
    print("Iniciando o tratador de arquivos de config....\n")

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #um desses funfa
    tcp.bind((ip_server, PORTAC_X))

    tcp.listen(5)

    while True:
        conn, addr = tcp.accept()
        
        #receber a qtd de bytes do json a ser recebido
        data = conn.recv(4)

        qtdBytes = struct.unpack('<i',data)[0]
        print("qtdBytes {}".format(qtdBytes))

        data = conn.recv(qtdBytes)
        #fechando a conexao
        conn.close()

        #formatando o cfg recebido
        cfg = json.loads(data)

        print('Nova configuração recebida')
        #printando o json recebido
        print(cfg)

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
        
        print('Configuração realizada')

    return

##aqui
def enviar_contratos(ip_ver, ip_dst, dst_port, contrato_obj):
    #print]("[enviar-contratos] p/ ip_dst: %s, port_dst: %s" %(host_ip, host_port))
    tempo_i = round(time.monotonic()*1000)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((ip_dst, dst_port))
 
    print("[%s] enviar contrato p/ %s\n" % (datetime.datetime.now().time(), ip_dst))

    #teste envio [ok]
    #tcp.connect(("10.123.123.2", host_port))

    # contratos_contador = 0
    # #contar quantos contratos enviar
    # for i in contratos:
    #     if i.ip_dst == ip_dst_contrato:
    #         contratos_contador = contratos_contador+1
    
    #enviar apenas um contrato
    contratos_contador = 1
    
    #enviar quantos contratos serao enviados
    tcp.send(struct.pack('<i',contratos_contador))

    #para cada contrato, antes de enviar, verificar o size e enviar o size do vetor de bytes a ser enviado
    #encontrar os contratos que se referem ao ip_dst informado e enviar para o host_ip:host_port

    vetorbytes = json.dumps(contrato_obj.toJSON()).encode('utf-8')
    qtdBytes = struct.pack('<i',len(vetorbytes))
    tcp.send(qtdBytes)
    tcp.send(vetorbytes)
    print(contrato_obj.toString())

    #fechando a conexao
    #print]("\n")
    tcp.close()
    print("[%s] enviar contrato p/ %s - fim\n" % (datetime.datetime.now().time(), ip_dst))
    # logging.info('[Packet_In] icmp 16 - enviar_contrato - fim - tempo: %d\n' % (round(time.monotonic()*1000) - tempo_i))
