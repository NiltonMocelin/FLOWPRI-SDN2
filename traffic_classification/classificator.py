
# 5-tuple (que eh o nome do arquivo pcap) : qtd_pacotes, tempo_ultima_inclusao

# importar o pacote de processamento
from sklearn.ensemble import RandomForestClassifier

flows_dict = {}

classificador = None

class ClassificacaoPayload:
    def __init__(self, classe_label:str, application_label:str, delay:int, bandwidth:int, priority:int, loss:int, jitter:int):
        self.classe_label = classe_label
        self.application_label = application_label
        self.bandwidth = bandwidth
        self.priority = priority
        self.loss = loss
        self.jitter = jitter
        self.delay = delay


def startRandomForest():

    classificador = RandomForestClassifier()

    return 


def classificar_fluxo(filename):

    classificacao_mock = ClassificacaoPayload("real", "video", 2000, 1, 1,10,10 )

    return classificacao_mock

def pkts_to_pcap(lista_pacotes, filename):
    return

def remover_file(filename):
    return

def classificar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt) -> ClassificacaoPayload:
    flow_five_tuple = ip_ver + "_" + ip_src + "_" + ip_dst + "_" + src_port + "_" + dst_port + "_" + proto
    #salvar em arqivo os pacotes,
    flows_dict[flow_five_tuple].append(pkt)
    
    if len(flows_dict[flow_five_tuple]) >=10:

        # pkts_to_pcap(flows_dict[flow_five_tuple], flow_five_tuple+".pcap")

        classificacao = classificar_fluxo(flow_five_tuple+".pcap")

        # remover_file(flow_five_tuple+".pcap")
        flows_dict[flow_five_tuple] = []

        return classificacao
    
    # fred_mock = { "label": "be", "banda":0, "prioridade":0, "classe":"be" }

    return ClassificacaoPayload("real", "video", 2000, 1, 1,10,10 )
