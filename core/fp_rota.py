class Rota_Node:
    def __init__(self, switch_name:int, in_port:int, out_port:int):
        self.switch_name:int = switch_name
        self.in_port:int = in_port
        self.out_port:int = out_port

class Rota:
    def __init__(self, ip_ver:int, src_prefix:str, dst_prefix:str, src_port:int,
                dst_port:int, proto:int, rota_nodes:list[Rota_Node]):

        self.src_prefix:int = src_prefix
        self.dst_prefix:int = dst_prefix
        self.ip_ver:int = ip_ver
        self.rota_nodes = rota_nodes # (nome_switch (str), porta_saida (int))
        self.src_port:int = src_port
        self.dst_port:int = dst_port
        self.proto:int = proto

## mudou:-: {} ip_dst: [rota_nodes]
rotas = {}

def get_rota(ip_src: str, ip_dst:str) -> list[Rota_Node]:
    
    lista_switches = rotas[ip_src+ip_dst]

    return lista_switches

def add_rota(ip_src: str, ip_dst:str, lista_rota_nodes:list[Rota_Node]):
    rotas[ip_src+ip_dst] = lista_rota_nodes

    return

def del_rota(ip_src:str, ip_dst:str):
    try:
        del rotas[ip_src+ip_dst]
        print("Rota removida")
    except:
        print("Rota inexistente")
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
        
        add_rota(src_prefix, dst_prefix, lista_rota_nodes)
        
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

        del_rota(src_prefix, dst_prefix)
        
    return 