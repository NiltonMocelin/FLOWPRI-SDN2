import threading

class Rota_Node:
    def __init__(self, switch_name:int, in_port:int, out_port:int):
        self.switch_name:int = switch_name
        self.in_port:int = in_port
        self.out_port:int = out_port

class Rota:
    def __init__(self, ip_ver:int, src_prefix:str, dst_prefix:str, src_port:int,
                dst_port:int, proto:int, rota_nodes:list):

        self.src_prefix:int = src_prefix
        self.dst_prefix:int = dst_prefix
        self.ip_ver:int = ip_ver
        self.rota_nodes = rota_nodes # (nome_switch (str), porta_saida (int))
        self.src_port:int = src_port
        self.dst_port:int = dst_port
        self.proto:int = proto

class RotaManager:
    def __init__(self):
        self.rotas = {}
        self.lock = threading.Lock()

    def get_rota(self,ip_src: str, ip_dst:str) -> list:
        
        lista_switches = self.rotas.get(ip_src+ip_dst, None)
    
        return lista_switches
    
    def add_rota(self,ip_src: str, ip_dst:str, lista_rota_nodes:list):
        with self.lock:
            self.rotas[ip_src+ip_dst] = lista_rota_nodes
        return
    
    def del_rota(self,ip_src:str, ip_dst:str):
        with self.lock:
            if self.rotas.pop(ip_src+ip_dst, None) == None:
                print("Rota inexistente")
                return    
        print("Rota removida")
        return

def tratador_addRotas(rotamanager:RotaManager, novasrotas_json):
    """{'src_prefix':'ip', 'dst_prefix':'ip', 'switches_rota':[{'nome_switch':1, 'porta_entrada':1, 'porta_saida':2, 'ordem'}]}"""
    print("Adicionando novas rotas:")
    for rota in novasrotas_json:
        #poderia obter uma lista de switches e ir em cada um adicinoando a rota
        src_prefix = rota['src_prefix']
        dst_prefix = rota['dst_prefix']

        lista_rota_nodes = []
        
        qtd_nohs = len(rota['switches_rota'])

        for switch in rota['switches_rota']:
            lista_rota_nodes.insert(switch['ordem'],Rota_Node(switch_name=switch['nome_switch'],in_port=switch['porta_entrada'],out_port=switch['porta_saida']))
        
        rotamanager.add_rota(src_prefix, dst_prefix, lista_rota_nodes)
        
    print('rotas adicionadas')

def tratador_delRotas(rotamanager:RotaManager, novasrotas_json):
    """{'src_prefix':'ip', 'dst_prefix':'ip'}"""
    for rota in novasrotas_json:
        #poderia obter uma lista de switches e ir em cada um adicinoando a rota
        src_prefix = rota['src_prefix']
        dst_prefix = rota['dst_prefix']
        rotamanager.del_rota(src_prefix, dst_prefix)
        
    return 