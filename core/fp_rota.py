class Rota_Node:
    def __init__(self, switch_name, in_port, out_port):
        self.switch_name = switch_name
        self.in_port = in_port
        self.out_port = out_port

class Rota:
    def __init__(self, ip_ver, src_prefix, dst_prefix, src_port,
                dst_port, proto, rota_nodes):

        self.src_prefix = src_prefix
        self.dst_prefix = dst_prefix
        self.ip_ver= ip_ver
        self.rota_nodes = rota_nodes # (nome_switch (str), porta_saida (int))
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto



#dado um conjunto de switches (var global) pertencentes a um dominio/controlador, recuperar o conjunto de switches que fazem parte da rota para o end destino/rede
def getRota_antigo(switch_primeiro_dpid, ip_dst):
	#por enquanto nao importam as rotas - rotas fixas e um switch
    #switches eh uma variavel global que compreende os switches do controlador
    #rota = vetor de switches
    rota = []
    ##print("[getRota] src:%s, dst:%s\n" % (ip_src, ip_dst))

    if switch_primeiro_dpid == None:
        for s in switches:
            if ip_dst in s.hosts:
                switch_primeiro_dpid = s.nome

    if switch_primeiro_dpid == None:
        return None

    #pegar o primeiro switch da rota, baseado no ip_Src --- ou, por meio do packet in, mas entao nao poderia criar as regras na criacao dos contratos
    switch_primeiro = getSwitchByName(str(switch_primeiro_dpid))
    rota.append(switch_primeiro)

    #pegar o salto do ultimo switch inserido na rota
    nextDpid = switch_primeiro.getPorta(switch_primeiro.getPortaSaida(ip_dst)).next #retorna inteiro

    #print("switch_primeiro: %s, nextDpid: %d\n" % (switch_primeiro.nome, nextDpid))

    while nextDpid > 0:
        s = getSwitchByName(nextDpid)
        rota.append(s)
        #se o .next da porta for -1, esse eh o switch de borda
        nextDpid = s.getPorta(s.getPortaSaida(ip_dst)).next
        
    #for r in rota:
        #print("[rota]: %s" % (r.nome))
            
    return rota

def get_rota(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, in_switch_id=-1):
    
    lista_switches = rotas[ip_dst]

    if in_switch_id == -1:
        return lista_switches

    #remover todos ate o primeiro elemento ser o switch
    for s in lista_switches:
        if s.switch_name != in_switch_id:
            lista_switches.remove(s)

    return lista_switches

def add_rota(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, lista_rota_nodes):
    rotas[ip_dst] = lista_rota_nodes

    return

def del_rota(ip_src, ip_dst, ip_ver, src_port, dst_port, proto, in_switch_id):
    return


def tratador_addRotas(novasrotas_json):

    print("Adicionando novas rotas:")
    for rota in novasrotas_json:
        #poderia obter uma lista de switches e ir em cada um adicinoando a rota
        ip_ver = rota['ip_ver']
        src_prefix = rota['src_prefix']
        dst_prefix = rota['dst_prefix']
        src_port = rota['src_port']
        dst_port = rota['dst_port']
        proto = rota['proto']
    
        lista_rota_nodes = []
        
        for switch in rota['switches_rota']:
            
            lista_rota_nodes.append(Rota_Node(switch_name=switch['nome_switch'],in_port=switch['porta_entrada'],out_port=switch['porta_saida']))
        
        add_rota(src_prefix, dst_prefix, ip_ver, src_port, dst_port, proto, lista_rota_nodes)
        
    print('rotas adicionadas')

def tratador_delRotas(novasrotas_json):

    for rota in novasrotas_json:
        #poderia obter uma lista de switches e ir em cada um adicinoando a rota
        ip_ver = rota['ip_ver']
        src_prefix = rota['src_prefix']
        dst_prefix = rota['dst_prefix']
        src_port = rota['src_port']
        dst_port = rota['dst_port']
        proto = rota['proto']

        
        for r in rotas:
            if r.ip_ver == ip_ver and r.src_prefix == src_prefix and r.dst_prefix == dst_prefix and r.src_port == src_port and r.dst_port == dst_port and r.proto == proto:
                rotas.remove(r)
                break 
        
    return 