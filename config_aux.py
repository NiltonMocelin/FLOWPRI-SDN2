        # if "addSwitches" in cfg:
        #     tratador_addSwitches(controller, cfg['addSwitches'])
        
        # if "delSwitches" in cfg:
        #     tratador_delSwitches(controller, cfg['delSwitches'])
            
        # if "addRotas" in cfg:
        #     tratador_addRotas(controller.rotamanager, cfg['addRotas'])
        
        # if "delRotas" in cfg:
        #     tratador_delRotas(controller.rotamanager, cfg['delRotas'])
        
        # if "addRegras" in cfg:
        #     tratador_addRegras(controller, cfg['addRegras'])
        
        # if "delRegras" in cfg:
        #     tratador_delRegras(controller, cfg['delRegras'])
        
        # if "setConfig" in cfg:
        #     tratador_setConfig(controller, cfg['setConfig'])
        # print('Configuração realizada')
import json
import socket
def prepare_addSwitch(server_ip, server_port):
    # data = {'addSwitch':[{'nome_switch' : integer, 'portas': [{'nome_porta': integer , 'banda_total': integer, 'proxSwitch':integer} ]}]}
    print("data = {'addSwitch':[{'nome_switch' : integer, 'portas': [{'nome_porta': integer , 'banda_total': integer, 'proxSwitch':integer} ]}]}")
    qtd_switches = int(input('Qtd switches ativos (int):'))
    data = {'addSwitch':[]}
    for j in range(0,qtd_switches):
        nome_switch=int(input('Nome Switch (dpid):'))
        qtd_portas = int(input('Qtd portas ativas (int):'))
        switch = {'nome_switch' : nome_switch, 'portas': []}
        for i in range(0,qtd_portas):
            nome_porta = int(input('Porta %d - Nome(int):'%(i)))
            banda_total = int(input('Porta %d - banda_total(int):'%(i)))
            proxSwitch = int(input('Porta %d - Prox Switch(int):'%(i)))
            switch['portas'].append({'nome_porta': nome_porta , 'banda_total': banda_total, 'proxSwitch':proxSwitch})
        data['addSwitch'].append(switch)
    
    # send
    enviar_msg(json.dumps(data), server_ip, server_port)
    return

def prepare_delSwitch():

    qtd_switches = input('Qtd switches remover (int):')

  
    return

def prepare_addRota(server_ip, server_port):
    # data = {'addRotas':[{'src_prefix' : str, 'dst_prefix': str, switches_rota': [{'nome_switch': integer , 'porta_entrada': integer, 'porta_saida':integer} ]}]}
    print("data = {'addRotas':[{'src_prefix' : str, 'dst_prefix': str, 'switches_rota': [{'nome_switch': integer , 'porta_entrada': integer, 'porta_saida':integer} ]}]}")
    qtd_rotas= int(input('Qtd rotas para inserir (int):'))
    data = {'addRota':[]}

    for j in range(0, qtd_rotas):
        src_prefix = input('Rota %d - src prefix(str):'%(i))
        dst_prefix = input('Rota %d - dst prefix(str):'%(i))
        qtd_switches = int(input('Rota %d - Qtd switches(int):'%(i)))
        rota = {'src_prefix' : src_prefix, 'dst_prefix': dst_prefix, 'switches_rota':[]}

        for i in range(0, qtd_switches):
            ordem_switch = int(input('Rota %d - Ordem Switch(int):'%(i)))
            nome_switch = int(input('Rota %d - nome_switch Switch(int):'%(i)))
            porta_entrada = int(input('Rota %d - Porta entrada (int):'%(i)))
            porta_saida =  int(input('Rota %d - Porta saida(int):'%(i)))
            switch = {'ordem' : ordem_switch, 'nome_switch': nome_switch, 'porta_entrada':porta_entrada, 'porta_saida':porta_saida} 
            rota['switches_rota'].append(switch)
        data['addRota'].append(rota)

    enviar_msg(json.dumps(data), server_ip, server_port)
    return

def prepare_delRota():


  
    return

def prepare_addRegra():


  
    return

def prepare_delRegra():


  
    return

def prepare_setConfig(server_ip, server_port):
    # data = {'setConfig':{'nome_config':str, 'valor':str}}

    print("data = {'setConfig':{'nome_config':str, 'valor':str}}")
    nome_config = input('Nome config (str):')
    valor = input('Valor config (str):')
    data = {'setConfig':{'nome_config':nome_config, 'valor':valor}}

    enviar_msg(json.dumps(data), server_ip, server_port)

    return

def prepare_addIPsDominio(controller, server_ip, server_port):
    # data = {'setConfig':{'nome_config':str, 'valor':str}}

    print("data = {'ips_dominio':[{'ip':str}]}")
    qtd_ips = int(input('Qtd ips:'))
    data = {'addIPsDominio':[]}
    for i in range(0, qtd_ips):
        valor = input('IP %d:'%(i))
        data['addIPsDominio'].append({'ip':valor})


    enviar_msg(json.dumps(data), server_ip, server_port)

    return



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

if __name__=='__main__':

    server_ip = input("Server IP ?:")
    server_port = int(input("Server Port ?:"))

    print("Opcoes:\n1 - addSwitch\t2 - addRota\t3 - setConfig:")
    opcao = int(input())

    if opcao == 1:
        prepare_addSwitch(server_ip, server_port)
    elif opcao == 2:
        prepare_addRota(server_ip, server_port)
    else:
        prepare_setConfig(server_ip, server_port)