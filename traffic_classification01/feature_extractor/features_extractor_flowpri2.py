### Negocio é o seguinte -> tem que estar o tráfego todo no mesmo arquivo (de ida e volta), dizer quem é o ip de origem, para poder identificar quem é o A (mais próximo da borda de origem) e quem é o B (mais distante da borda de origem).

from scapy.utils import PcapReader
from scapy.all import IP, UDP, TCP, Padding, Raw

from .TIME_features import Time_features
from .PKT_features import PKT_features

#para poder executar o tcptrace
import subprocess



def tratar_tcptrace(saida_tcptrace, two_way= True, debug= False):
    """ Aqui tem que modifinar manualmente conforme quer o resultado:
    Entrada: tcptrace csv -> Separa a saída do tcptrace em uma lista de strings. Ajusta valores como N/Y e NA para numérico"""

    # substituir N/Y por = ?
    # substituir NA por = ?
    # substituir N por = ?
    # substituir Y por = ?
    linhas = saida_tcptrace.split("\n")

    #aqui precisava um teste de sanidade: -> descobrir pcaps que foram escritos errado (aparentemente aconteceu)
    # if len(linhas) != xx:
    #     exit(0)

    index_cabecalho = 0
    for linha in linhas:
        if 'conn_#' in linha:
            break
        index_cabecalho+=1

    lista_cabecalho = linhas[index_cabecalho].replace(" ","").split(',')
    lista_resultados = linhas[index_cabecalho+2].replace(" ","").split(',')

    #quero remover esses campos (sao os primeiros):: {'conn_#', 'host_a', 'host_b', 'port_a', 'port_b',}

    lista_resultados.pop(0) # con
    lista_resultados.pop(0) # host_a
    lista_resultados.pop(0) # host_b
    lista_resultados.pop(0) # port_a
    lista_resultados.pop(0) # port_b

    lista_cabecalho.pop(0) # con
    lista_cabecalho.pop(0) # host_a
    lista_cabecalho.pop(0) # host_b
    lista_cabecalho.pop(0) # port_a
    lista_cabecalho.pop(0) # port_b

    # ajustar campos para numéricos
    # NA == 0
    # N/Y == 0.5
    # Y/Y == 1
    # Y/N == 0.7
    # N/N == 0
    # N ==  0
    # Y == 1
    # colunas problemáticas>
    #    [ 34 ] SYN/FIN_pkts_sent_a2b  :  0/0
    #    [ 35 ] SYN/FIN_pkts_sent_b2a  :  0/0
    #    [ 36 ] req_1323_ws/ts_a2b  :  N/Y
    #    [ 37 ] req_1323_ws/ts_b2a  :  N/Y
    #    [ 40 ] req_sack_a2b  :  N
    #    [ 41 ] req_sack_b2a  :  N
    #    [ 76 ] ttl_stream_length_a2b  :  NA
    #    [ 77 ] ttl_stream_length_b2a  :  NA
    #    [ 78 ] missed_data_a2b  :  NA
    #    [ 79 ] missed_data_b2a  :  NA

    for i in range(34, 36):
        if lista_resultados[i] == '1/1':
            lista_resultados[i] = '1'
        elif lista_resultados[i] == '0/0':
            lista_resultados[i] = '0'
        else:
            lista_resultados[i] = '0.5'

    for i in range(36, 42):
        if lista_resultados[i] == 'N':
            lista_resultados[i]= '0'
        elif lista_resultados[i] == 'Y':
            lista_resultados[i]= '1'
        elif lista_resultados[i] == 'Y/Y':
            lista_resultados[i]= '1'
        elif lista_resultados[i] == 'N/Y':
            lista_resultados[i]= '0.25'
        elif lista_resultados[i] == 'Y/N':
            lista_resultados[i]= '0.5'
        else:
            lista_resultados[i]= '0'

    for i in range(76, 80):
        if lista_resultados[i] == 'NA':
            lista_resultados[i]= '0'

    # se for one-way, remover todos os b2a
    if two_way == False:
        for i in range(len(lista_resultados)-1, -1, -1):
            if 'b2a' in lista_cabecalho[i]:
                lista_cabecalho.pop(i)
                lista_resultados.pop(i)

    # remover o ultimo valor q eh vazio, por causa da virgula após o último valor valido  0,123,3123,
    lista_cabecalho.pop()
    lista_resultados.pop()

    if debug:
        print(' -- tcptrace -- ')
        for i in range(0, len(lista_cabecalho)):
            print('[',i,'] ', lista_cabecalho[i] , ' = ',  lista_resultados[i])
        print('tcptrace lista_cabecalho: ', len(lista_cabecalho))
        print('tcptrace lista_resultados: ', len(lista_resultados))

    return lista_resultados, lista_cabecalho


def process_bloco(id_bloco, host_a, proto, service_class, app_class, qos_class, bloco_total, two_ways, debug=False):# -> tuple[list, list]:
    """     id_bloco = contador de blocos para o subfluxo
            class_label = como sera rotulado
            proto = protocolo (TCP ou UDP)
            two_ways = True or False -> são pacotes apenas de ida ou tem ida e volta ? (existem features específicas para ida e para volta)
            bloco_total = bloco com todos os pacotes do bloco
            bloco_ab/ba = caso queira adicinonar informacoes sobre os pacote two ways
    """
    
    proc_time = Time_features(bloco_total= bloco_total, host_a=host_a, proto=proto, two_way=two_ways)

    proc_pkt = PKT_features(bloco_total= bloco_total, host_a=host_a, proto=proto, two_way=two_ways)
        
    if two_ways:
        proc_time.calcular_tudo()
        proc_pkt.calcular_tudo()
    else:
        proc_time.calcular_ab()
        proc_pkt.calcular_ab()
    
    port_a =''
    port_b =''
    host_b =''

    if bloco_total[0][IP].src == host_a:
        host_b = bloco_total[0][IP].dst
        port_a = bloco_total[0][proto].sport
        port_b = bloco_total[0][proto].dport
    else:
        host_b = bloco_total[0][IP].src
        port_a = bloco_total[0][proto].dport
        port_b = bloco_total[0][proto].sport

    
    
    # saida deve ser string ou lista de strings ? --> escolhi lista de strs
    # concatenando os resultados e as colunas
    resultados_saida = [host_a, host_b, port_a, port_b, 0 if proto=='TCP' else 1, str(id_bloco), service_class, app_class, qos_class, len(bloco_total)] + proc_time.get_lista_resultados() + proc_pkt.get_lista_resultados()
    colunas_saida = ['host_a', 'host_b', 'a_port', 'b_port', 'proto', 'id_bloco', 'service_class', 'app_class', 'qos_class', 'qtd_pkts_total'] + proc_time.get_lista_processados() + proc_pkt.get_lista_processados()

    
    if debug:
        print('processando : ', len(bloco_total), 'pkts - ', host_a, ' -> ', host_b)
        print('time_features: ', len(proc_time.get_lista_resultados()), ' - ', len(proc_time.get_lista_processados()))
        print('pkt_features: ', len(proc_pkt.get_lista_resultados()), ' - ', len(proc_pkt.get_lista_processados()))

        proc_time.teste()
        proc_pkt.teste()
        headers = proc_time.gerar_cabecalho() + ';'+ proc_pkt.gerar_cabecalho()
        print(headers)
        print(resultados_saida)
        print('resultados_meu: ', len(resultados_saida))
        print('colunas_meu: ', len(colunas_saida))

    return resultados_saida, colunas_saida


#cara ficou muito complexo, melhor separar em processar_tcp, processar_udp, processar one-way, processar two-ways
def extrair_features(id_bloco, host_a, proto, service_class, app_class, qos_class, entrada_arquivo_pcap, two_way= True, tcptrace = True, debug=False):
    """Requisitos: 
        1- preparar o arquivo pcap com o bloco de pacotes
        2- preparar a lista com o bloco de pacotes
        Saida: colunas e uma linha de features separadas por virgula (os dois em string)
    """
    #ler arquivo
    # pcaps = rdpcap(entrada_arquivo_pcap)
    bloco_total = []

    for pkt in PcapReader(entrada_arquivo_pcap):
        # ler o bloco
        bloco_total.append(pkt)

    # chamar o processador de blocos
    resultados_saida, colunas_saida = process_bloco(id_bloco=id_bloco, host_a=host_a, proto=proto, service_class= service_class, app_class= app_class, qos_class=qos_class, bloco_total=bloco_total, two_ways= two_way, debug = debug)

    #invocar tcptrace no mesmo bloco
    #tcptrace -l -r -W -u -G --csv --xplot_all_files --xplot_args="" --output_dir="" --output_prefix="" facebook_audio1a.pcap
    
    if tcptrace:
        result = subprocess.run(["tcptrace", "-l", "-r", "-W", "-u", "--csv", entrada_arquivo_pcap], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        resultados_tcptrace, colunas_tcptrace = tratar_tcptrace(result.stdout, two_way=two_way)

        #juntando as listas de colunas e resultados
        resultados_saida = resultados_saida + resultados_tcptrace
        colunas_saida = colunas_saida + colunas_tcptrace

    # processar as duas saidas
    return resultados_saida, colunas_saida