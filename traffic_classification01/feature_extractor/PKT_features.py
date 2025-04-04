from .utils import *

class PKT_features:

    def __init__(self, bloco_total, host_a, proto, two_way=False):

        self.lista_resultados = []
        self.lista_processados = []

        self.bloco_total = bloco_total
        self.proto = proto
        self.two_way = two_way

        self.bloco_ab = None
        self.bloco_ba = None

        if two_way:
            self.bloco_ab = []
            self.bloco_ba = []

            for pkt in bloco_total:
                if pkt[IP].src == host_a:
                    self.bloco_ab.append(pkt)
                else:
                    self.bloco_ba.append(pkt)
        

    def get_lista_processados(self):
        return self.lista_processados
    
    def get_lista_resultados(self):
        return [str(val) for val in self.lista_resultados]

    def gerar_cabecalho(self):
        return ';'.join(self.lista_processados)
  
    def gerar_resultados(self):
        return ';'.join(self.get_lista_resultados())

    def calcular_tudo(self):

        # server_port, client_port, get_protocol
        # self.server_port()
        # self.client_port()
        # self.get_protocol()

        # as funcoes que quero rodar tem esses padrões de nome
        lista_funcoes = []
        #mean_med_std_min_max_q1_q3
        #total_packets_ba, total_packets_ab
        #pkts_
        #payload_
        #bytes_
        for func in dir(self):
            if 'mean_med' in func or 'pkts_' in func or 'payload_' in func or 'bytes_' in func:
                lista_funcoes.append(func)

        #run
        for func in lista_funcoes:
            getattr(self,func)()

        return self.gerar_resultados()
    
    def calcular_ab(self):
        # para poder realizar os calculos sem medo
        self.bloco_ab = self.bloco_total

        # server_port, client_port, get_protocol
        # self.server_port()
        # self.client_port()
        # self.get_protocol()

        # as funcoes que quero rodar tem esses padrões de nome
        lista_funcoes = []
        #mean_med_std_min_max_q1_q3
        #total_packets_ba, total_packets_ab
        #pkts_
        #payloads_
        #bytes_
        for func in dir(self):
            if 'ab_mean_med' in func or 'ab_pkts_' in func or 'ab_payload_' in func or 'ab_bytes_' in func:
                lista_funcoes.append(func)

        #run
        for func in lista_funcoes:
            getattr(self,func)()

        return self.gerar_resultados()
    
    def teste(self):
        tam_proc = len(self.lista_processados)
        tam_res = len(self.lista_resultados)
        if tam_proc > tam_res:
            print("Tem mais cabecalho do que resultado")
        elif tam_proc < tam_res:
            print("tem mais resultado do que cabeçalho")
        else:
            print("Certinho!!")

    #######################################################################################################
    ### Portas
    def server_port(self):
        """Server Port Port Number at server; we can establish server and
        client ports as we limit ourselves to flows for which we see the initial connection set-up"""
    
        self.lista_processados.append("server_port_ref1")
        self.lista_resultados.append(self.bloco_total[0][self.proto].dport)
        
    def client_port(self):
        """Client Port Port Number at client"""
    
        self.lista_processados.append("client_port_ref2")
        self.lista_resultados.append(self.bloco_total[0][self.proto].sport)
    
    
        #transporte - tcp/udp
    def get_protocol(self):
        self.lista_processados.append("proto")
        retorno = '0' if self.proto == 'TCP' else '0'
        self.lista_resultados.append(retorno)
        return retorno
        
    
    #### ethernet
    def mean_med_std_min_max_q1_q3_data_pkt(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("mean_data_pkt_ref13")
        self.lista_processados.append("med_data_pkt_ref12")
        self.lista_processados.append("std_data_pkt_ref16")
        self.lista_processados.append("min_data_pkt_ref10")
        self.lista_processados.append("max_data_pkt_ref15")
        self.lista_processados.append("q1_data_pkt_ref11")
        self.lista_processados.append("q3_data_pkt_ref14")

        lista_valores = []

        for pkt in self.bloco_total:
            lista_valores.append(len(pkt))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

    def mean_med_std_min_max_q1_q3_header_ip(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("mean_header_ip_ref27")
        self.lista_processados.append("med_header_ip_ref26")
        self.lista_processados.append("std_header_ip_ref30")
        self.lista_processados.append("min_header_ip_ref24")
        self.lista_processados.append("max_header_ip_ref29")
        self.lista_processados.append("q1_header_ip_ref25")
        self.lista_processados.append("q3_header_ip_ref28")

        lista_valores = []

        for pkt in self.bloco_total:
            lista_valores.append(len(pkt[IP]) - len(pkt[IP].payload))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

    def mean_med_std_min_max_q1_q3_data_ip(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("mean_data_ip_ref20")
        self.lista_processados.append("med_data_ip_ref19")
        self.lista_processados.append("std_data_ip_ref23")
        self.lista_processados.append("min_data_ip_ref17")
        self.lista_processados.append("max_data_ip_ref22")
        self.lista_processados.append("q1_data_ip_ref18")
        self.lista_processados.append("q3_data_ip_ref21")

        lista_valores = []

        for pkt in self.bloco_total:
            lista_valores.append(len(pkt[IP].payload))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

        
    def mean_med_std_min_max_q1_q3_data_control(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("mean_data_control_ref27")
        self.lista_processados.append("med_data_control_ref26")
        self.lista_processados.append("std_data_control_ref30")
        self.lista_processados.append("min_data_control_ref24")
        self.lista_processados.append("max_data_control_ref29")
        self.lista_processados.append("q1_data_control_ref25")
        self.lista_processados.append("q3_data_control_ref28")

        lista_valores = []

        for pkt in self.bloco_total:
            lista_valores.append(len(pkt[self.proto]))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

    def mean_med_std_min_max_q1_q3_data_payload(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("mean_data_payload_ref300")
        self.lista_processados.append("med_data_payload_ref301")
        self.lista_processados.append("std_data_payload_ref302")
        self.lista_processados.append("min_data_payload_ref303")
        self.lista_processados.append("max_data_payload_ref304")
        self.lista_processados.append("q1_data_payload_ref305")
        self.lista_processados.append("q3_data_payload_ref306")

        lista_valores = []

        for pkt in self.bloco_total:
            lista_valores.append(len(pkt[self.proto].payload))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))



    def ab_mean_med_std_min_max_q1_q3_data_pkt(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ab_mean_data_pkt_156")
        self.lista_processados.append("ab_med_data_pkt_155")
        self.lista_processados.append("ab_var_data_pkt_159")
        self.lista_processados.append("ab_min_data_pkt_153")
        self.lista_processados.append("ab_max_data_pkt_158")
        self.lista_processados.append("ab_q1_data_pkt_154")
        self.lista_processados.append("ab_q3_data_pkt_157")

        lista_valores = []

        for pkt in self.bloco_ab:
            lista_valores.append(len(pkt))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))


    def ab_mean_med_std_min_max_q1_q3_header_ip(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ab_mean_header_ip_ref321")
        self.lista_processados.append("ab_med_header_ip_ref322")
        self.lista_processados.append("ab_std_header_ip_ref323")
        self.lista_processados.append("ab_min_header_ip_ref324")
        self.lista_processados.append("ab_max_header_ip_ref325")
        self.lista_processados.append("ab_q1_header_ip_ref326")
        self.lista_processados.append("ab_q3_header_ip_ref327")

        lista_valores = []

        for pkt in self.bloco_ab:
            lista_valores.append(len(pkt[IP]) - len(pkt[IP].payload))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))


    def ab_mean_med_std_min_max_q1_q3_data_ip(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ab_mean_data_ip_163")
        self.lista_processados.append("ab_med_data_ip_162")
        self.lista_processados.append("ab_var_data_ip_166")
        self.lista_processados.append("ab_min_data_ip_160")
        self.lista_processados.append("ab_max_data_ip_165")
        self.lista_processados.append("ab_q1_data_ip_161")
        self.lista_processados.append("ab_q3_data_ip_164")

        lista_valores = []

        for pkt in self.bloco_ab:
            lista_valores.append(len(pkt[IP]))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

    def ab_mean_med_std_min_max_q1_q3_data_control(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ab_mean_data_control_163")
        self.lista_processados.append("ab_med_data_control_162")
        self.lista_processados.append("ab_var_data_control_166")
        self.lista_processados.append("ab_min_data_control_160")
        self.lista_processados.append("ab_max_data_control_165")
        self.lista_processados.append("ab_q1_data_control_161")
        self.lista_processados.append("ab_q3_data_control_164")

        lista_valores = []

        for pkt in self.bloco_ab:
            lista_valores.append(len(pkt[self.proto]))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))



    def ab_mean_med_std_min_max_q1_q3_data_payload(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ab_min_data_control_307")
        self.lista_processados.append("ab_q1_data_control_308")
        self.lista_processados.append("ab_med_data_control_309")
        self.lista_processados.append("ab_mean_data_control_310")
        self.lista_processados.append("ab_q3_data_control_311")
        self.lista_processados.append("ab_max_data_control_312")
        self.lista_processados.append("ab_var_data_control_313")

        lista_valores = []

        for pkt in self.bloco_ab:
            lista_valores.append(len(pkt[self.proto].payload))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

    def ba_mean_med_std_min_max_q1_q3_data_pkt(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ba_mean_data_pkt_177")
        self.lista_processados.append("ba_med_data_pkt_176")
        self.lista_processados.append("ba_var_data_pkt_180")
        self.lista_processados.append("ba_min_data_pkt_174")
        self.lista_processados.append("ba_max_data_pkt_179")
        self.lista_processados.append("ba_q1_data_pkt_175")
        self.lista_processados.append("ba_q3_data_pkt_178")

        lista_valores = []

        for pkt in self.bloco_ba:
            lista_valores.append(len(pkt))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))


    def ba_mean_med_std_min_max_q1_q3_header_ip(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ba_mean_header_ip_ref191")
        self.lista_processados.append("ba_med_header_ip_ref190")
        self.lista_processados.append("ba_std_header_ip_ref194")
        self.lista_processados.append("ba_min_header_ip_ref188")
        self.lista_processados.append("ba_max_header_ip_ref193")
        self.lista_processados.append("ba_q1_header_ip_ref189")
        self.lista_processados.append("ba_q3_header_ip_ref192")

        lista_valores = []

        for pkt in self.bloco_ba:
            lista_valores.append(len(pkt[IP]) - len(pkt[IP].payload))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))


    def ba_mean_med_std_min_max_q1_q3_data_ip(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ba_mean_data_ip_184")
        self.lista_processados.append("ba_med_data_ip_183")
        self.lista_processados.append("ba_var_data_ip_187")
        self.lista_processados.append("ba_min_data_ip_181")
        self.lista_processados.append("ba_max_data_ip_186")
        self.lista_processados.append("ba_q1_data_ip_182")
        self.lista_processados.append("ba_q3_data_ip_185")

        lista_valores = []

        for pkt in self.bloco_ba:
            lista_valores.append(len(pkt[IP]))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

    def ba_mean_med_std_min_max_q1_q3_data_control(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ba_mean_data_control_184")
        self.lista_processados.append("ba_med_data_control_183")
        self.lista_processados.append("ba_var_data_control_187")
        self.lista_processados.append("ba_min_data_control_181")
        self.lista_processados.append("ba_max_data_control_186")
        self.lista_processados.append("ba_q1_data_control_182")
        self.lista_processados.append("ba_q3_data_control_185")

        lista_valores = []

        for pkt in self.bloco_ba:
            lista_valores.append(len(pkt[self.proto]))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

    def ba_mean_med_std_min_max_q1_q3_data_payload(self):
        """calcular todos de uma vez (mais rápido)"""
        self.lista_processados.append("ba_min_data_control_314")
        self.lista_processados.append("ba_q1_data_control_315")
        self.lista_processados.append("ba_med_data_control_316")
        self.lista_processados.append("ba_mean_data_control_317")
        self.lista_processados.append("ba_q3_data_control_318")
        self.lista_processados.append("ba_max_data_control_319")
        self.lista_processados.append("ba_var_data_control_320")

        lista_valores = []

        for pkt in self.bloco_ba:
            lista_valores.append(len(pkt[self.proto].payload))
        
        self.lista_resultados.append(calcular_mean(lista_valores))
        self.lista_resultados.append(calcular_median(lista_valores))
        self.lista_resultados.append(calcular_std(lista_valores))
        self.lista_resultados.append(calcular_min(lista_valores))
        self.lista_resultados.append(calcular_max(lista_valores))
        self.lista_resultados.append(calcular_q1(lista_valores))
        self.lista_resultados.append(calcular_q3(lista_valores))

    def pkts_header_sum(self):
        self.lista_processados.append('pkts_header_sum')
        header_s = 0.0
        for pkt in self.bloco_total:
            header_s += len(pkt[self.proto]) - len(pkt[self.proto].payload)
        self.lista_resultados.append(header_s)
        return header_s

    def pkts_length_sum(self):
        self.lista_processados.append('pkts_len_sum')
        soma = 0
        contador = 0
        #comecar do segundo pacote no self.bloco_total
        for pkt in self.bloco_total:
            soma += len(pkt)
            contador +=1 
        self.lista_resultados.append(soma/contador if contador > 0 else soma)
        return soma/contador
    
    def pkts_per_second(self):
        self.lista_processados.append('pkts_per_sec')
        duracao = self.bloco_total[-1].time - self.bloco_total[0].time
        retorno = len(self.bloco_total)/float(duracao) if duracao > 0 else len(self.bloco_total)
        self.lista_resultados.append(retorno)
        return retorno
    
    #pegar um subflow inteiro - retorna alguma informacao que representa a largura de banda do subflow (media?, mediana?, maior?)
    def bytes_per_secs(self):
        """bytes per second Total number of bytes / per observed time"""
        self.lista_processados.append('bytes_per_sec')

        if self.bloco_total == []:
            self.lista_resultados.append(0)
            return 0

        #media em bytes
        soma = 0.0
        for i in self.bloco_total:
            soma+= len(i)
    
        #em segundos
        duracao = float(self.bloco_total[-1].time - self.bloco_total[0].time)
    
        if duracao == 0:
            return '0'
    
        #bytes/segundo
        lbanda = soma/duracao if duracao > 0 else soma
        retorno = lbanda / 1000
        #normalizar em 15mbps
        retorno = retorno / 15000
        #obter em kbps
        self.lista_resultados.append(retorno)
        return retorno
    
    def ab_pkts_header_sum(self):
        self.lista_processados.append('ab_pkts_header_sum')
        header_s = 0.0
        for pkt in self.bloco_ab:
            header_s += len(pkt[self.proto]) - len(pkt[self.proto].payload)
        self.lista_resultados.append(header_s)
        return header_s

    def ab_pkts_length_sum(self):
        self.lista_processados.append('ab_pkts_len_sum')
        soma = 0
        contador = 0
        #comecar do segundo pacote no self.bloco_total
        for pkt in self.bloco_ab:
            soma += len(pkt)
            contador +=1 
        self.lista_resultados.append(soma)
        return soma

    def ab_pkts_per_second(self):
        self.lista_processados.append('ab_pkts_per_sec')
        if self.bloco_ab == []:
            self.lista_resultados.append(0)
            return 0        

        duracao = self.bloco_ab[-1].time - self.bloco_ab[0].time

        retorno = len(self.bloco_ab)/float(duracao) if duracao > 0 else len(self.bloco_ab)
        self.lista_resultados.append(retorno)
        return retorno
    
    #pegar um subflow inteiro - retorna alguma informacao que representa a largura de banda do subflow (media?, mediana?, maior?)
    def ab_bytes_per_secs(self):
        """bytes per second Total number of bytes / per observed time"""
        self.lista_processados.append('ab_bytes_per_sec')

        if self.bloco_ab == []:
            self.lista_resultados.append(0)
            return 0

        #media em bytes
        soma = 0.0
        for i in self.bloco_ab:
            soma+= len(i)

        #em segundos
        duracao = float(self.bloco_ab[-1].time - self.bloco_ab[0].time)
            
        #bytes/segundo
        lbanda = soma/duracao if duracao > 0 else soma
        retorno = lbanda / 1000
        #normalizar em 15mbps
        retorno = retorno / 15000
        #obter em kbps
        self.lista_resultados.append(retorno)
        return retorno
    
    def ba_pkts_header_sum(self):
        self.lista_processados.append('ba_pkts_header_sum')
        header_s = 0.0
        for pkt in self.bloco_ba:
            header_s += len(pkt[self.proto]) - len(pkt[self.proto].payload)
        self.lista_resultados.append(header_s)
        return header_s

    def ba_pkts_length_sum(self):
        self.lista_processados.append('ba_pkts_len_sum')
        soma = 0
        contador = 0
        #comecar do segundo pacote no self.bloco_total
        for pkt in self.bloco_ba:
            soma += len(pkt)
            contador +=1 
        self.lista_resultados.append(soma)
        return soma

    def ba_pkts_per_second(self):
        self.lista_processados.append('ba_pkts_per_sec')
        duracao = self.bloco_total[-1].time - self.bloco_total[0].time
        tam_bloco = len(self.bloco_total)
        retorno = tam_bloco/float(duracao) if duracao > 0 else tam_bloco
        self.lista_resultados.append(retorno)
        return retorno
    
    #pegar um subflow inteiro - retorna alguma informacao que representa a largura de banda do subflow (media?, mediana?, maior?)
    def ba_bytes_per_secs(self):
        """bytes per second Total number of bytes / per observed time"""
        self.lista_processados.append('ba_bytes_per_sec') 

        if self.bloco_ba == []:
            self.lista_resultados.append(0)
            return 0    

        #media em bytes
        soma = 0.0
        for i in self.bloco_total:
            soma+= len(i)
    
        #em segundos
        duracao = float(self.bloco_total[-1].time - self.bloco_total[0].time)

        #bytes/segundo
        lbanda = soma/duracao if duracao > 0 else soma
        retorno = lbanda / 1000
        #normalizar em 15mbps
        retorno = retorno / 15000
        #obter em kbps
        self.lista_resultados.append(retorno)
        return retorno

    def total_packets_ab(self):
        """31 total packets a b The total number of packets seen (client->server)."""
        self.lista_processados.append("ab_total_pkts_ref31")
        retorno = len(self.bloco_ab)
        self.lista_resultados.append(retorno)
        return retorno
    
    def total_packets_ba(self):
        """32 total packets b a The total number of packets seen (server->client)."""
        self.lista_processados.append("ba_total_pkts_ref32")
        retorno = len(self.bloco_ba)
        self.lista_resultados.append(retorno)
        return retorno

################### tamanho dos pacotes bloco_total ######################
        #quantidade de pacotes que sao maiores que a media
    def pkts_above_media(self):
        self.lista_processados.append('pkts_abv_mean')

        if self.bloco_total == []:
            self.lista_resultados.append(0)    
            return 0

            #media
        soma = 0.0
        tamanho = 0
        for pkt in self.bloco_total:
            soma += len(pkt)
            tamanho+=1
        retorno = soma/tamanho if tamanho > 0 else soma
    
        media = retorno
    
        contador = 0
        for pkt in self.bloco_total:
            if len(pkt)>media:
                contador +=1
        self.lista_resultados.append(contador)
        return contador
    
    def pkts_below_media(self):
        self.lista_processados.append('pkts_bel_mean')

        if self.bloco_total == []:
            self.lista_resultados.append(0)
            return 0
        
            #media
        soma = 0.0
        tamanho = 0
        for pkt in self.bloco_total:
            soma += len(pkt)
            tamanho+=1
        retorno = soma/tamanho if tamanho > 0 else soma
    
        media = retorno
    
        contador = 0
        for pkt in self.bloco_total:
            if len(pkt)<=media:
                contador +=1
        self.lista_resultados.append(contador)
        return contador
    
    # of pkts whose payload lengths are below 128
    def payload_bellow_128(self):
        self.lista_processados.append('pays_bel_128')
        contador = 0 
        for pkt in self.bloco_total:
            payload = len(pkt[self.proto].payload)
            if(payload < 128):
                contador+=1
        self.lista_resultados.append(contador)
        return contador

    def payload_between_128_1024(self):
        self.lista_processados.append('pays_in_128_1024')
        contador = 0 
        for pkt in self.bloco_total:
            payload = len(pkt[self.proto].payload)
            if(payload >= 128 and payload < 1024):
                contador+=1
        self.lista_resultados.append(contador)
        return contador

    # pld_bin_inf: # of pkts whose payload lengths are above 1024
    def payload_above_1024(self): 
        self.lista_processados.append('pays_abv_1024')
        contador = 0 
        for pkt in self.bloco_total:
            payload = len(pkt[self.proto].payload)
           
            if(payload >= 1024):
                contador+=1
        self.lista_resultados.append(contador)
        return contador
    
################# pacotes A->B ###############
        #quantidade de pacotes que sao maiores que a media
    def ab_pkts_above_media(self):
        self.lista_processados.append('ab_pkts_abv_mean')

        if self.bloco_ab == []:
            self.lista_resultados.append(0)
            return 0
    
            #media
        soma = 0.0
        tamanho = 0
        for pkt in self.bloco_ab:
            soma += len(pkt)
            tamanho+=1
        retorno = soma/tamanho if tamanho > 0 else soma
    
        media = retorno
    
        contador = 0
        for pkt in self.bloco_ab:
            if len(pkt)>media:
                contador +=1
        self.lista_resultados.append(contador)
        return contador
    
    def ab_pkts_below_media(self):
        self.lista_processados.append('ab_pkts_bel_mean')
            #media
        soma = 0.0
        tamanho = 0
        for pkt in self.bloco_ab:
            soma += len(pkt)
            tamanho+=1
        retorno = soma/tamanho if tamanho > 0 else soma
    
        media = retorno
    
        contador = 0
        for pkt in self.bloco_ab:
            if len(pkt)<=media:
                contador +=1
        
        self.lista_resultados.append(contador)
        return contador
    
    # of pkts whose payload lengths are below 128
    def ab_payload_bellow_128(self):
        self.lista_processados.append('ab_pays_bel_128')
        contador = 0 
        for pkt in self.bloco_ab:
            payload = len(pkt[self.proto].payload)
            if(payload < 128):
                contador+=1
        
        self.lista_resultados.append(contador)
        return contador

    def ab_payload_between_128_1024(self):
        self.lista_processados.append('ab_pays_in_128_1024')
        contador = 0 
        for pkt in self.bloco_ab:
            payload = len(pkt[self.proto].payload)
            if(payload >= 128 and payload < 1024):
                contador+=1
        
        self.lista_resultados.append(contador)
        return contador

    # pld_bin_inf: # of pkts whose payload lengths are above 1024
    def ab_payload_above_1024(self): 
        self.lista_processados.append('ab_pkts_abv_1024')
        contador = 0 
        for pkt in self.bloco_ab:
            payload = len(pkt[self.proto].payload)
            if(payload >= 1024):
                contador+=1
        self.lista_resultados.append(contador)
        return contador
    
###################     pacotes B->A    ##############
    #quantidade de pacotes que sao maiores que a media
    def ba_pkts_above_media(self):
        self.lista_processados.append('ba_pkts_abv_mean')

        if self.bloco_ba:
            self.lista_resultados.append(0)
            return 0    

            #media
        soma = 0.0
        tamanho = len(self.bloco_ba)
        for pkt in self.bloco_ba:
            soma += len(pkt)
        retorno = soma/tamanho if tamanho > 0 else soma
    
        media = retorno
    
        contador = 0
        for pkt in self.bloco_ba:
            if len(pkt)>media:
                contador +=1
        self.lista_resultados.append(contador)
        return contador
    
    def ba_pkts_below_media(self):
        self.lista_processados.append('ba_pkts_bel_mean')
        if self.bloco_ba == []:
            self.lista_resultados.append(0)
            return 0

            #media
        soma = 0.0
        tamanho = len(self.bloco_ba)
        for pkt in self.bloco_ba:
            soma += len(pkt)
        retorno = soma/tamanho if tamanho > 0 else soma
    
        media = retorno
    
        contador = 0
        for pkt in self.bloco_ba:
            if len(pkt)<=media:
                contador +=1
        
        self.lista_resultados.append(contador)
        return contador
    
    # of pkts whose payload lengths are below 128
    def ba_payload_below_128(self):
        self.lista_processados.append('ba_pays_bel_128')
        contador = 0 
        for pkt in self.bloco_ba:
            payload = len(pkt[self.proto].payload)
            if(payload < 128):
                contador+=1
        self.lista_resultados.append(contador)
        return contador

    def ba_payload_between_128_1024(self):
        self.lista_processados.append('ba_pays_in_128_1024')
        contador = 0 
        for pkt in self.bloco_ba:
            payload = len(pkt[self.proto].payload)
            if(payload >= 128 and payload < 1024):
                contador+=1
        
        self.lista_resultados.append(contador)
        return contador

    # pld_bin_inf: # of pkts whose payload lengths are above 1024
    def ba_payload_above_1024(self): 
        self.lista_processados.append('ba_pays_abv_1024')
        contador = 0 
        for pkt in self.bloco_ba:
            payload = len(pkt[self.proto].payload)
            if(payload >= 1024):
                contador+=1
        self.lista_resultados.append(contador)
        return contador


    # #nao esta exatamente correto pq exige que o bloco seja um subflow valido, tanto faz
    # def get_subflow_duration(self):
    #     self.lista_processados.append('subflow_duration')
    #     timestampi = self.bloco_total[0].time
    #     timestampf = self.bloco_total[-1].time
    #     retorno = float(timestampf-timestampi)
    #     self.lista_resultados.append(retorno)
    #     return retorno
       