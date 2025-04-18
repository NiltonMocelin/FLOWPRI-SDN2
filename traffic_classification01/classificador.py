import time

# 5-tuple (que eh o nome do arquivo pcap) : qtd_pacotes, tempo_ultima_inclusao

# importar o pacote de processamento
from sklearn.ensemble import RandomForestClassifier
import os
from ryu.lib import pcaplib 
# from scapy.utils import PcapWriter # usando o pcaplib instead

TCP = 6
UDP = 17

from core.fp_constants import SC_REAL, SC_NONREAL, SC_BEST_EFFORT
from .feature_extractor.features_extractor_flowpri2 import extrair_features

flows_dict = {}

classificador = None

class ClassificacaoPayload:
    def __init__(self, classe:int, classe_label:str, application_label:str, delay:int, bandwidth:int, priority:int, loss:int, jitter:int):
        self.classe_label = classe_label
        self.classe = classe
        self.application_label = application_label
        self.bandwidth = bandwidth
        self.priority = priority
        self.loss = loss
        self.jitter = jitter
        self.delay = delay


def startRandomForest():

    classificador = RandomForestClassifier()

    return 


def classificar_fluxo(ip_ver, ip_src, proto, lista_pacotes_bytes, filename):
    
    ##### testando lib pcaplib para escrever o arquivo pcap
    # salvar em .pcap --- classificadores diferentes caso seja tcp ou udp
    file_pcap = open(filename, 'wb')
    pwr = pcaplib.Writer(file_pcap) # aqui as vezes o formato de arquivo importa, cuidado, ver como o extrator original fazia

    for pkt_bytes in lista_pacotes_bytes:
        pwr.write_pkt(buf=pkt_bytes, ts = time.time()) #,timestamp (ver como vai acontecer sem o timestamp primeiro)
    file_pcap.flush()
    file_pcap.close()
    ###### testando a lib pcaplib

    proto_string = "TCP"

    if proto == UDP:
        proto_string = "UDP"
    
    #id=0, pq so tem um bloco == gera uma linha
    resultado_saida, resultado_colunas = extrair_features(id_bloco=0, host_a=ip_src, proto=proto_string, service_class='classe', app_class='app', qos_class='qos', entrada_arquivo_pcap=filename, two_way=False, tcptrace=True if proto == 6 else False)

    # Normalizar os valores !!

    print("Resultados features para classificacao: ")
    print(resultado_colunas)
    print(resultado_saida)

    # ajustar esse payload com o payload do fred e da blockchain ==> classe precisa ser int para o fred, mas no blockchain payload é str.. ==> foi ajustado, classe eh int, application_label eh string. Quando tem label eh string. O classe_label no fim nao sera utilizado na transacao
    classificacao_mock = ClassificacaoPayload(classe = SC_REAL,classe_label="real", application_label="video", bandwidth=2000, delay=1, priority=1,loss=10, jitter=0 )

    os.remove(filename)
    return classificacao_mock


def classificar_pacote(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, pkt_bytes, reiniciar:bool=False) -> ClassificacaoPayload:
    flow_five_tuple = "%d_%s_%s_%d_%d_%d" %(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
    #salvar em arqivo os pacotes,

    
    if not os.path.exists('classificacoes'):
        os.makedirs('classificacoes')

    if flow_five_tuple in flows_dict:
        if reiniciar:
            flows_dict[flow_five_tuple] = []
        flows_dict[flow_five_tuple].append(pkt_bytes)
    else:
        flows_dict[flow_five_tuple] = [pkt_bytes]

    qtd_pkts = len(flows_dict[flow_five_tuple]) 
    print("[classificar-pkt] Obtidos %d pacotes para a classificacao" % (qtd_pkts))
    if qtd_pkts >=10:

        # pkts_to_pcap(flows_dict[flow_five_tuple], flow_five_tuple+".pcap")

        classificacao = classificar_fluxo(ip_ver, ip_src, proto, flows_dict[flow_five_tuple], 'classificacoes/%s.pcap'%(flow_five_tuple))

        # remover_file(flow_five_tuple+".pcap")
        flows_dict[flow_five_tuple] = []
        print("[classificar-pkt] finalizada -> classe:%d, classe label:%s, application label:%s, bw:%d, delay:%d, priority:%d, loss:%d, jitter:%d" % 
              (classificacao.classe, classificacao.classe_label, classificacao.application_label,classificacao.bandwidth,classificacao.delay,
               classificacao.priority,classificacao.loss, classificacao.jitter))

        return classificacao
    
    # fred_mock = { "label": "be", "banda":0, "prioridade":0, "classe":"be" }

    return None # nao classificado
