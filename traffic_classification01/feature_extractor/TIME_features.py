from .utils import *

class Time_features:

    def __init__(self, bloco_total, host_a, proto, two_way = False):

        self.lista_processados = []
        self.lista_resultados = []

        self.lista_IAT_total = []
        self.lista_IAT_ab = []

        self.lista_IAT_ba = []

        self.two_way = two_way

        self.proto = proto

        self.bloco_total = bloco_total

        self.set_list(bloco_total, self.lista_IAT_total)

        self.bloco_ab = None
        self.bloco_ba = None
        contador = 0 
        if two_way:
            self.bloco_ab = []
            self.bloco_ba = []

            for pkt in bloco_total:
                contador += 1
                # print('[',contador,']',pkt)
                if pkt['IP'].src == host_a:
                    self.bloco_ab.append(pkt)
                else:
                    self.bloco_ba.append(pkt)
            self.set_list(self.bloco_ab, self.lista_IAT_ab)
            self.set_list(self.bloco_ba, self.lista_IAT_ba)

    def set_list(self, bloco, lista_IAT):
        #limpando entradas anteriores
        lista_IAT.clear()

        prev_time = float(bloco[0].time) if bloco != [] else 0.0

        for pkt in bloco:
            lista_IAT.append(float(pkt.time) - prev_time)
            prev_time = pkt.time

    def get_lista_processados(self):
        return self.lista_processados
    
    def get_lista_resultados(self):
        return [str(val) for val in self.lista_resultados]

    def gerar_resultados(self):
        return ';'.join(self.get_lista_resultados())
        # saida = ''
        # for valor in self.lista_resultados:
        #     saida += ";"+str(valor)

        # return saida.removeprefix(';')
    
    def gerar_cabecalho(self):
        return ';'.join(self.lista_processados)
        # saida = ''
        # for valor in self.lista_processados:
        #     saida += ";"+str(valor)

        # return saida.removeprefix(';')

    def calcular_tudo(self):

        if not self.two_way:
            return self.calcular_ab()

        # rodar todas as funcoes que possuem IAT no nome
        lista_funcoes = []
        for func in dir(self):
            if "mean_med" in func:
                lista_funcoes.append(func)
        
        #rodando cada uma
        for func in lista_funcoes:
            getattr(self, func)()

        #as unicas que não possuem IAT no nomes No_transitions_bulkTrans, Time_spent_in_bulk, Duration_Connection_duration, bulk_Percent_of_time_spent, Time_spent_idle, idle_Percent_of_time
        self.No_transitions_bulkTrans()
        self.Time_spent_in_bulk()
        self.Duration_Connection_duration()
        self.bulk_Percent_of_time_spent()
        self.Time_spent_idle()
        self.idle_Percent_of_time()

        return self.gerar_resultados()
    
    def calcular_ab(self):
        #para poder calcular sem medo
        self.bloco_ab = self.bloco_total

        self.set_list(self.bloco_total, self.lista_IAT_ab)
        
        # rodar todas as funcoes que possuem IAT no nome
        lista_funcoes = []
        for func in dir(self):
            if "ab_mean_med" in func:
                lista_funcoes.append(func)
        
        #rodando cada uma
        for func in lista_funcoes:
            getattr(self, func)()

        #as unicas que não possuem IAT no nomes No_transitions_bulkTrans, Time_spent_in_bulk, Duration_Connection_duration, bulk_Percent_of_time_spent, Time_spent_idle, idle_Percent_of_time
        self.No_transitions_bulkTrans()
        self.Time_spent_in_bulk()
        self.Duration_Connection_duration()
        self.bulk_Percent_of_time_spent()
        self.Time_spent_idle()
        self.idle_Percent_of_time()

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

    ###IAT
    def mean_med_std_min_max_q1_q3_IAT(self):
        self.lista_processados.append("mean_IAT_ref6")
        self.lista_processados.append("med_IAT_ref5")
        self.lista_processados.append("min_IAT_ref3")
        self.lista_processados.append("q1_IAT_ref4")
        self.lista_processados.append("q3_IAT_ref3")
        self.lista_processados.append("max_IAT_ref8")
        self.lista_processados.append("std_IAT_ref9")
        self.lista_processados.append("sum_IAT")
        self.lista_processados.append("below_mean_IAT")
        self.lista_processados.append("above_mean_IAT")
        self.lista_resultados.append(calcular_mean(self.lista_IAT_total))
        self.lista_resultados.append(calcular_median(self.lista_IAT_total))
        self.lista_resultados.append(calcular_min(self.lista_IAT_total))
        self.lista_resultados.append(calcular_q1(self.lista_IAT_total))
        self.lista_resultados.append(calcular_q3(self.lista_IAT_total))
        self.lista_resultados.append(calcular_max(self.lista_IAT_total))
        self.lista_resultados.append(calcular_std(self.lista_IAT_total))
        self.lista_resultados.append(calcular_sum(self.lista_IAT_total))
        self.lista_resultados.append(calcular_menor_media(self.lista_IAT_total))
        self.lista_resultados.append(calcular_maior_media(self.lista_IAT_total))
        

    def ab_mean_med_std_min_max_q1_q3_IAT(self):
        self.lista_processados.append("ab_mean_IAT_198")
        self.lista_processados.append("ab_med_IAT_197")
        self.lista_processados.append("ab_std_IAT_201")
        self.lista_processados.append("ab_min_IAT_195")
        self.lista_processados.append("ab_max_IAT_200")
        self.lista_processados.append("ab_q1_IAT_196")
        self.lista_processados.append("ab_q3_IAT_199")
        self.lista_processados.append("ab_sum_IAT")
        self.lista_processados.append("ab_below_mean_IAT")
        self.lista_processados.append("ab_above_mean_IAT")
        self.lista_resultados.append(calcular_mean(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_median(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_std(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_min(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_max(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_q1(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_q3(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_sum(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_menor_media(self.lista_IAT_ab))
        self.lista_resultados.append(calcular_maior_media(self.lista_IAT_ab))

    def ba_mean_med_std_min_max_q1_q3_IAT(self):
        self.lista_processados.append("ba_mean_IAT_205")
        self.lista_processados.append("ba_med_IAT_204")
        self.lista_processados.append("ba_std_IAT_208")
        self.lista_processados.append("ba_min_IAT_202")
        self.lista_processados.append("ba_max_IAT_207")
        self.lista_processados.append("ba_q1_IAT_203")
        self.lista_processados.append("ba_q3_IAT_206")
        self.lista_processados.append("ba_sum_IAT")
        self.lista_processados.append("ba_below_mean_IAT")
        self.lista_processados.append("ba_above_mean_IAT")
        self.lista_resultados.append(calcular_mean(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_median(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_std(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_min(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_max(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_q1(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_q3(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_sum(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_menor_media(self.lista_IAT_ba))
        self.lista_resultados.append(calcular_maior_media(self.lista_IAT_ba))
        
    def No_transitions_bulkTrans(self):
        """210 No. transitions bulk/trans The number of transitions between transaction mode and bulk transfer mode,
        where bulk transfer mode is defined as the time when there are more than three successive packets in
        the same direction without any packets carrying data in the other direction"""
        self.lista_processados.append("No_transitions_bulkTrans_210")

        if self.bloco_total == []:
            self.lista_resultados.append(0)
            return 0

        sip = self.bloco_total[0].src
        sport = self.bloco_total[0][self.proto].sport

        contador_pacotes = 0
        contador_bulk = 0

        for pkt in self.bloco_total:
            try:
                if len(pkt[self.proto].payload)  < 1:
                    contador_pacotes = 0
                    continue

                if pkt[IP].src == sip and pkt[self.proto].sport == sport:
                    contador_pacotes += 1
                else:
                    contador_pacotes -= 1

                if contador_pacotes > 3 or contador_pacotes <3:
                    contador_bulk+=1
            except:
                continue

        self.lista_resultados.append(contador_bulk)
        return contador_bulk

    # o que é bulk transfer mode: is defined as the time when there are more than three successive packets in
        # the same direction without any packets carrying data in the other direction"""
    def Time_spent_in_bulk(self, silent=False):
        """211 Time spent in bulk Amount of time spent in bulk transfer mode -- silent pq tem outra funcao que utiliza o resultado"""

        if self.bloco_total == []:
            if not silent:
                self.lista_processados.append("Time_spent_in_bulk_211")
                self.lista_resultados.append(0)
            return 0

        prev_time = self.bloco_total[0].time
        contador_pacotes = 0

        time_spent_bulk_mode = 0

        sip = self.bloco_total[0].src
        sport = self.bloco_total[0][self.proto].sport

        for pkt in self.bloco_total:
            if len(pkt[self.proto].payload)  < 1:
                contador_pacotes = 0
                prev_time = pkt.time
                continue

            if pkt[IP].src == sip and pkt[self.proto].sport == sport:
                contador_pacotes += 1
            else:
                contador_pacotes -= 1
            
            if contador_pacotes > 3 or contador_pacotes <3:
                time_spent_bulk_mode += pkt.time - prev_time
                prev_time = pkt.time

        if not silent:
            self.lista_processados.append("Time_spent_in_bulk_211")
            self.lista_resultados.append(time_spent_bulk_mode)
        return time_spent_bulk_mode

    def Duration_Connection_duration(self):
        """212 Duration Connection duration"""
        self.lista_processados.append("Duration_Connection_duration_212")

        if self.bloco_total == []:
            self.lista_resultados.append(0)
            return 0
        
        resultado = float(self.bloco_total[-1].time - self.bloco_total[0].time)
        self.lista_resultados.append(resultado)
        return resultado

    def bulk_Percent_of_time_spent(self):
        """213 % bulk Percent of time spent in bulk transfer"""
        self.lista_processados.append("bulk_Percent_of_time_spent_213")
        if self.bloco_total == []:
            self.lista_resultados.append(0)
            return 0
        duration_connection = float(self.bloco_total[-1].time - self.bloco_total[0].time)

        time_bulk = self.Time_spent_in_bulk(silent=True)
        resultado =  time_bulk/ duration_connection if duration_connection >0 else time_bulk
        self.lista_resultados.append(resultado)
        return resultado

    def Time_spent_idle(self):
        """214 Time spent idle The time spent idle (where idle time is the accumulation of all periods of 2 seconds or greater when no
        packet was seen in either direction)"""
        self.lista_processados.append("Time_spent_idle_214")

        resultado = calcular_sum(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado

    def idle_Percent_of_time(self):
        """215 % idle Percent of time spent idle"""
        self.lista_processados.append("idle_Percent_of_time_215")
        if self.bloco_total == []:
            self.lista_resultados.append(0)
            return 0

        duration_connection = float(self.bloco_total[-1].time - self.bloco_total[0].time)
        time_idle = float(calcular_sum(self.lista_IAT_total))
        if time_idle == 0:
            self.lista_resultados.append(0)
            return 0    
        resultado = duration_connection / time_idle
        self.lista_resultados.append(resultado)
        return resultado

# acho que esse está errado!!
    # def Time_since_last_connection(self):
    #     """209 Time since last connection Time since the last connection between these hosts"""
    #     self.lista_processados.append("Time_since_last_connection_209")
    #     # O tempo entre um FYN e o próximo SYN ACK ? Se tiver vários, tirar a media OU pegar só a última ocorrencia. 
    #     lista_tempos = []
    #     prev_tempo = 0
        
    #     if self.proto != 'TCP':
    #         return 0

    #     for pkt in self.bloco:
    #         if check_FYN_flag(pkt):
    #             prev_tempo = pkt.time
            
    #         if check_SYN_flag(pkt):
    #             lista_tempos.append(prev_tempo-pkt.time)

    #     return lista_tempos[-1]
########################### Unitarios

    def min_IAT(self):
        """3 min_IAT: Minimum packet inter-arrival time for all packets of
    the flow (considering both directions)."""

        self.lista_processados.append("min_IAT_ref3")
        resultado = calcular_min(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado

    def q1_IAT(self):
        """4 q1_IAT: First quartile inter-arrival time"""
        self.lista_processados.append("q1_IAT_ref4")
        resultado = calcular_q1(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado

    def med_IAT(self):
        """5 med_IAT: Median inter-arrival time"""
        self.lista_processados.append("med_IAT_ref5")

        resultado = calcular_median(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado

    def mean_IAT(self):
        """6 mean_IAT: Mean inter-arrival time"""
        self.lista_processados.append("mean_IAT_ref6")
        resultado = calcular_mean(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado
    
    def q3_IAT(self):
        """3 q3_IAT Maximum packet inter-arrival time"""
        self.lista_processados.append("q3_IAT_ref3")
        resultado = calcular_q3(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado
    
    def max_IAT(self):
        """8 max_IAT Maximum packet inter-arrival time"""
        self.lista_processados.append("max_IAT_ref8")
        resultado = calcular_max(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado

    def std_IAT(self):
        """9 std_IAT: Standard Variation: in packet inter-arrival time"""
        self.lista_processados.append("std_IAT_ref9")
        resultado = calcular_std(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado
        
    def sum_IAT(self):
        """comparar com  pkt_IAT algo assim .... sem referencia"""
        self.lista_processados.append("sum_IAT")
        resultado = calcular_sum(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado
        
    def above_mean_IAT(self):
        """Calcula quantos IATs estão acima da média """
        self.lista_processados.append("above_mean_IAT")
        resultado = calcular_maior_media(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado
        
    def below_mean_IAT(self):
        """Calcula quantos IATs estão abaixo da média """
        self.lista_processados.append("below_mean_IAT")
        resultado = calcular_menor_media(self.lista_IAT_total)
        self.lista_resultados.append(resultado)
        return resultado

    def min_IAT_ab(self):
        """195 min IAT a b Minimum of packet inter-arrival time (client→server)"""
        self.lista_processados.append("min_IAT_ab_195")
        resultado = calcular_min(self.lista_IAT_ab)
        self.lista_resultados.append(resultado)
        return resultado
        
    def q1_IAT_ab(self):
        """196 q1 IAT a b First quartile of packet inter-arrival time"""
        self.lista_processados.append("q1_IAT_ab_196")
        resultado = calcular_q1(self.lista_IAT_ab)
        self.lista_resultados.append(resultado)
        return resultado
        
    def med_IAT_ab(self):
        """197 med IAT a b Median of packet inter-arrival time"""
        self.lista_processados.append("med_IAT_ab_197")
        resultado = calcular_median(self.lista_IAT_ab)
        self.lista_resultados.append(resultado)
        return resultado
        
    def mean_IAT_ab(self):
        """198 mean IAT a b Mean of packet inter-arrival time"""
        self.lista_processados.append("mean_IAT_ab_198")
        resultado = calcular_mean(self.lista_IAT_ab)
        self.lista_resultados.append(resultado)
        return resultado
        
    def q3_IAT_ab(self):
        """199 q3 IAT a b Third quartile of packet inter-arrival time"""
        self.lista_processados.append("q3_IAT_ab_199")
        resultado = calcular_q3(self.lista_IAT_ab)
        self.lista_resultados.append(resultado)
        return resultado
        
    def max_IAT_ab(self):
        """200 max IAT a b Maximum of packet inter-arrival time"""
        self.lista_processados.append("max_IAT_ab_200")
        resultado = calcular_max(self.lista_IAT_ab)
        self.lista_resultados.append(resultado)
        return resultado
    
    def var_IAT_ab(self):
        """201 var IAT a b Variance of packet inter-arrival time"""
        self.lista_processados.append("var_IAT_ab_201")
        resultado = calcular_var(self.lista_IAT_ab)
        self.lista_resultados.append(resultado)
        return resultado
    
    def min_IAT_ba(self):
        """202 min IAT b a Minimum of packet inter-arrival time (server→client)"""
        self.lista_processados.append("min_IAT_ba_202")
        resultado = calcular_min(self.lista_IAT_ba)
        self.lista_resultados.append(resultado)
        return resultado
        
    def q1_IAT_ba(self):
        """203 q1 IAT b a First quartile of packet inter-arrival time"""
        self.lista_processados.append("q1_IAT_ba_203")
        resultado = calcular_q1(self.lista_IAT_ba)
        self.lista_resultados.append(resultado)
        return resultado
        
    def med_IAT_ba(self):
        """204 med IAT b a Median of packet inter-arrival time"""
        self.lista_processados.append("med_IAT_ba_204")
        resultado = calcular_median(self.lista_IAT_ba)
        self.lista_resultados.append(resultado)
        return resultado
        
    def mean_IAT_ba(self):
        """205 mean IAT b a Mean of packet inter-arrival time"""
        self.lista_processados.append("mean_IAT_ba_205")
        resultado = calcular_mean(self.lista_IAT_ba)
        self.lista_resultados.append(resultado)
        return resultado
        
    def q3_IAT_ba(self):
        """206 q3 IAT b a Third quartile of packet inter-arrival time"""
        self.lista_processados.append("q3_IAT_ba_206")
        resultado = calcular_q3(self.lista_IAT_ba)
        self.lista_resultados.append(resultado)
        return resultado
        
    def max_IAT_ba(self):
        """207 max IAT b a Maximum of packet inter-arrival time"""
        self.lista_processados.append("max_IAT_ba_207")
        resultado = calcular_max(self.lista_IAT_ba)
        self.lista_resultados.append(resultado)
        return resultado
        
    def var_IAT_ba(self):
        """208 var IAT b a Variance of packet inter-arrival time"""
        self.lista_processados.append("var_IAT_ba_208")
        resultado = calcular_var(self.lista_IAT_ba)
        self.lista_resultados.append(resultado)
        return resultado
    # #Fourier Fast Transform (FFT)...
    # def FFT_all(self):
    #     """219 FFT all FFT of packet IAT (arctan of the top-ten frequencies ranked by the magnitude of their contribution) (all
    #     traffic) (Frequency #1)"""
    #     self.lista_processados.append("FFT_all_219")

    #     lista_IAT = self.get_list_IAT_total()

    #     lista_IAT.sort()

    #     #obter os 10 primeiros e gerar o FFT deles ?

    #     return '0'

    # def FFT_all2(self):
    #     """220 FFT all ” (Frequency #2)"""
    #     self.lista_processados.append("FFT_all2_220")
    #     return '0'

    # def FFT_all3(self):
    #     """221 FFT all ” ..."""
    #     self.lista_processados.append("FFT_all3_221")
    #     return '0'

    # def FFT_all4(self):
    #     """222 FFT all ” ..."""
    #     self.lista_processados.append("FFT_all4_222")
    #     return '0'

    # def FFT_all5(self):
    #     """223 FFT all ” ..."""
    #     self.lista_processados.append("FFT_all5_223")
    #     return '0'

    # def FFT_all6(self):
    #     """224 FFT all ” ..."""
    #     self.lista_processados.append("FFT_all6_224")
    #     return '0'

    # def FFT_all7(self):
    #     """225 FFT all ” ..."""
    #     self.lista_processados.append("FFT_all7_225")
    #     return '0'

    # def FFT_all8(self):
    #     """226 FFT all ” ..."""
    #     self.lista_processados.append("FFT_all8_226")
    #     return '0'

    # def FFT_all9(self):
    #     """227 FFT all ” ..."""
    #     self.lista_processados.append("FFT_all9_227")
    #     return '0'

    # def FFT_all_10(self):
    #     """228 FFT all ” (Frequency #10)"""
    #     self.lista_processados.append("FFT_all_10_228")
    #     return '0'

    # def FFT_ab_1(self):
    #     """229 FFT a b FFT of packet IAT (arctan of the top-ten frequencies ranked by the magnitude of their contribution)
    #     (client→server) (Frequency #1)"""
    #     self.lista_processados.append("FFT_ab_1_229")
    #     return '0'

    # def FFT_ab_2(self):
    #     """230 FFT a b ” (Frequency #2)"""
    #     self.lista_processados.append("FFT_ab_2_230")
    #     return '0'

    # def FFT_ab_3(self):
    #     """231 FFT a b ” ..."""
    #     self.lista_processados.append("FFT_ab_3_231")
    #     return '0'

    # def FFT_ab_4(self):
    #     """232 FFT a b ” ..."""
    #     self.lista_processados.append("FFT_ab_4_232")
    #     return '0'

    # def FFT_ab_5(self):
    #     """233 FFT a b ” ..."""
    #     self.lista_processados.append("FFT_ab_5_233")
    #     return '0'

    # def FFT_ab_6(self):
    #     """234 FFT a b ” ..."""
    #     self.lista_processados.append("FFT_ab_6_234")
    #     return '0'

    # def FFT_ab_7(self):
    #     """235 FFT a b ” ..."""
    #     self.lista_processados.append("FFT_ab_7_235")
    #     return '0'

    # def FFT_ab_8(self):
    #     """236 FFT a b ” ..."""
    #     self.lista_processados.append("FFT_ab_8_236")
    #     return '0'

    # def FFT_ab_9(self):
    #     """237 FFT a b ” ..."""
    #     self.lista_processados.append("FFT_ab_9_237")
    #     return '0'

    # def FFT_ab_10(self):
    #     """238 FFT b a ” (Frequency #10)"""
    #     self.lista_processados.append("FFT_ab_10_238")
    #     return '0'

    # def FFT_ba_1(self):
    #     """239 FFT b a FFT of packet IAT (arctan of the top-ten frequencies ranked by the magnitude of their contribution)
    #     (server→client) (Frequency #1)"""
    #     self.lista_processados.append("FFT_ba_1_239")
    #     return '0'

    # def FFT_ba_2(self):
    #     """240 FFT b a ” ..."""
    #     self.lista_processados.append("FFT_ba_2_240")
    #     return '0'

    # def FFT_ba_3(self):
    #     """241 FFT b a ” ..."""
    #     self.lista_processados.append("FFT_ba_3_241")
    #     return '0'

    # def FFT_ba_4(self):
    #     """242 FFT b a ” ..."""
    #     self.lista_processados.append("FFT_ba_4_242")
    #     return '0'

    # def FFT_ba_5(self):
    #     """243 FFT b a ” ..."""
    #     self.lista_processados.append("FFT_ba_5_243")
    #     return '0'

    # def FFT_ba_6(self):
    #     """244 FFT b a ” ..."""
    #     self.lista_processados.append("FFT_ba_6_244")
    #     return '0'

    # def FFT_ba_7(self):
    #     """245 FFT b a ” ..."""
    #     self.lista_processados.append("FFT_ba_7_245")
    #     return '0'

    # def FFT_ba_8(self):
    #     """246 FFT b a ” ..."""
    #     self.lista_processados.append("FFT_ba_8_246")
    #     return '0'

    # def FFT_ba_9(self):
    #     """247 FFT b a ” ..."""
    #     self.lista_processados.append("FFT_ba_9_247")
    #     return '0'

    # def FFT_ba_10(self):
    #     """248 FFT b a ” (Frequency #10)"""
    #     self.lista_processados.append("FFT_ba_10_248")
    #     return '0'
