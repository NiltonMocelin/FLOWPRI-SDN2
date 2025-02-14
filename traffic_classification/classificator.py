
# 5-tuple (que eh o nome do arquivo pcap) : qtd_pacotes, tempo_ultima_inclusao

# importar o pacote de processamento
from sklearn.ensemble import RandomForestClassifier

flows_dict = {}

classificador = None

def startRandomForest():

    classificador = RandomForestClassifier()

    return 


def classificar_fluxo(filename):

    fred_mock = { "label": "video", "banda":2000, "prioridade":1, "classe":"video_real" }

    return fred_mock

def pkts_to_pcap(lista_pacotes, filename):
    return

def remover_file(filename):
    return

def processar_pacotes(flow_five_tuple, pkt):
    #salvar em arqivo os pacotes,
    flows_dict[flow_five_tuple].append(pkt)
    
    if len(flows_dict[flow_five_tuple]) >=10:

        # pkts_to_pcap(flows_dict[flow_five_tuple], flow_five_tuple+".pcap")

        classificacao = classificar_fluxo(flow_five_tuple+".pcap")

        # remover_file(flow_five_tuple+".pcap")
        flows_dict[flow_five_tuple] = []

        return classificacao
    
    fred_mock = { "label": "be", "banda":0, "prioridade":0, "classe":"be" }

    return fred_mock