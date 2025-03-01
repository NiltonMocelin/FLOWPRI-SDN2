from fp_acao import Acao
from fp_porta import Porta
from fp_constants import CPT, ALL_TABLES, CRIAR, REMOVER, FORWARD_TABLE, CLASSIFICATION_TABLE, ANY_PORT, NO_METER, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT, BE_HARD_TIMEOUT, BE_IDLE_TIMEOUT, SEMBANDA, EMPRESTANDO, NAOEMPRESTANDO
from fp_constants import FILA_C1P1, FILA_C1P2, FILA_C1P3, FILA_C2P1, FILA_C2P2, FILA_C2P3, FILA_BESTEFFORT, FILA_CONTROLE, NO_QOS_MARK, class_prio_to_queue_id, SC_REAL, SC_NONREAL, SC_BEST_EFFORT, SC_CONTROL
from fp_regra import Regra, getRegrasExpiradas
import sys

from fp_openflow_rules import addRegraF, addRegraM, delRegraM, delRegraF, getMeterID_from_Flow, delMeter, generateMeterId


class Switch:
    def __init__(self, datapath, name:int, controller): 
        
        print("Novo switch: nome = S%s" % (str(name)))

        self.controller = controller

        self.datapath = datapath
        self.nome = name
        self.portas = []

        #Como adicionar itens a um dicionario -> dicio['idade'] = 20
        self.macs = {} #chave: mac, valor: porta
        self.redes = {} #chave: ip, valor: porta
        self.hosts= {} #chave: ip, valor: mac

        #5-tuple : id
        self.meter_dict = {}

    def addPorta(self, nomePorta:int, larguraBanda:int, proximoSwitch:int):
        print("[S%s] Nova porta: porta=%s, banda=%s, proximoSalto=%s\n" % (str(self.nome), str(nomePorta), str(larguraBanda), str(proximoSwitch)))
        #criar a porta no switch
        self.portas.append(Porta(nomePorta, int(larguraBanda), int(int(larguraBanda)*.33), int(int(larguraBanda)*.35), 0, 0, int(proximoSwitch)))

    def delPorta(self, nomePorta:int):
        # print("[S%s] deletando: porta=%s, banda=%s, proximoSalto=%s\n" % (str(self.nome), str(nomePorta), str(larguraBanda), str(proximoSwitch)))
        
        index = 0
        porta = None
        for i in range(0, len(self.portas)):
            if self.portas[i].nome == nomePorta:
                index = i
                porta = self.portas[i]
        
        if porta == None:
            print('porta %s não encontrada' % (str(nomePorta)))
            return

        for regra in porta.getRegrasC1() + porta.getRegrasC2():
            delRegraF(self, regra.ip_ver, regra.ip_src, regra.ip_dst, regra.src_port, regra.dst_port, regra.proto)

        self.portas.pop(index)
        return 

    def getQueueId(self, classe, prioridade):
        return class_prio_to_queue_id[classe*10+prioridade]

    def getPorta(self, nomePorta:int) -> Porta:

        for i in self.portas:
            # %s x %s\n" % (i.nome, nomePorta))
            if i.nome == nomePorta:
                return i
        #print("[getPorta] porta inexistente: %s\n" % (nomePorta))
        return None
    
    def getPortas(self)->list[Porta]:
        return self.portas
    
    def addRegraBE(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida):

        porta_saida = self.getPorta(porta_saida).addRegra(Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, ANY_PORT, porta_saida, NO_METER, 0, 0, 0, FILA_BESTEFFORT, '{"qos_mark":%d, "out_port":%d, "meter_id":%d}' %(NO_QOS_MARK, porta_saida, NO_METER), False))
        addRegraF(self, ip_ver, ip_src, ip_dst, porta_saida, src_port, dst_port, proto, FILA_BESTEFFORT, NO_METER, NO_QOS_MARK, BE_IDLE_TIMEOUT, BE_HARD_TIMEOUT)

        return True

    def addRegraQoSBackbone(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, flow_label:int, banda:int, prioridade:int, classe:int, fila:int, qos_mark:int, porta_nome_armazenar_regra:int, criarMeter:bool, criarOpenFlow:bool):
        #Criar regras agrupadas, como em:[linha: 846] https://github.com/faucetsdn/ryu/blob/master/ryu/ofproto/ofproto_v1_3_parser.py
        #match = parser.OFPMatch(vlan_vid=(0x1000, 0x1000))
        return

    def addRegraQoS(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, flow_label:int, banda:int, prioridade:int, classe:int, fila:int, qos_mark:int, porta_nome_armazenar_regra:int, criarMeter:bool, criarOpenFlow:bool):

    #adiciona uma regra, na porta entrada e saida, criar meter
        meter_id = NO_METER
        if criarMeter:
            meter_id = generateMeterId(self)
            addRegraM(self, banda, meter_id)

            #armazenar meter
            self.meter_dict[str(ip_ver)+ip_src+ip_dst+str(src_port)+str(dst_port)+str(proto)] = meter_id
        
        self.getPorta(porta_nome_armazenar_regra).addRegra(Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, meter_id, banda, prioridade, classe, fila, flow_label, '{"qos_mark":%d, "out_port":%d, "meter_id":%d}' %(NO_QOS_MARK, porta_saida, meter_id), emprestando))
        if criarOpenFlow:
            addRegraF(self, ip_ver, ip_src, ip_dst, porta_saida, src_port, dst_port, proto, fila, meter_id, qos_mark, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT)
            # addRegraF(porta_saida)

        return True
    
    # def delRegraQoS(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, flow_label:int, banda:int, prioridade:int, classe:int, fila:int, emprestando:bool):
        
    #     self.delRegra(ip_ver,ip_src,ip_dst,src_port,dst_port,proto,porta_saida)
    #     self.delRegra(ip_ver,ip_src,ip_dst,src_port,dst_port,proto,porta_entrada)
        
    #     return True
    
    def delRegra(self,ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_nome:int, removerMeter:bool):
    #remove uma regra

        if removerMeter:
            meter_id = getMeterID_from_Flow(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)

            if meter_id != NO_METER: # qos 
                delRegraM(meter_id)
                delMeter(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)

        self.getPorta(porta_nome).delRegra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
        delRegraF(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)

        return True

#porta_switch antes era dport -> eh a porta onde a regra vai ser salva -> porta de saida do switch
    def GBAM(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, banda:int, prioridade:int, classe:int):
        """ Parametros:
        ip_ver: str
        ip_src: str
        ip_dst: str
        src_port:str
        dst_port:str
        proto:str
        porta_saida:str
        banda:str
        prioridade:str
        classe:str
        """

        # tem uma diferenca do GBAM de borda e do gbam backbone....

        # verificar se e
        print("[alocarGBAM-S%d] porta %d, src: %s, dst: %s, banda: %d, prioridade: %d, classe: %d \n" % (self.nome, porta_saida, ip_src, ip_dst,banda, prioridade, classe))

        #caso seja classe de controle ou best-effort, nao tem BAM, mas precisa criar regras da mesma forma
        #best-effort
        if classe == SC_BEST_EFFORT:
            self.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida)
            return True

        #controle
        if classe == SC_CONTROL:
            addRegraF(switch=self, qos_mark=NO_QOS_MARK, prioridade=100, hard_timeout=BE_HARD_TIMEOUT, idle_timeout=BE_IDLE_TIMEOUT, flow_removed=False, ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst, out_port=porta_saida, src_port=src_port, dst_port=dst_port, proto=proto, fila=FILA_CONTROLE,meter_id=None,flag=0)
            return True

        # fazer porta entrada e depois porta de saida
        # as duas devem alocar 
        return self._alocarGBAM_borda(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, banda, prioridade, classe)

    def _alocarGBAM_borda(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, banda:int, prioridade:int, classe:int) -> list[Acao] :
        """Criar em porta de entrada significa: essa regra deve ser salva na porta de entrada ? = Sim -> apenas armazena a regra e reduz a banda;;; Não, é na porta de saída -> entrao armazena a regra, reduz a banda e cria a regra openflow nos switches para traffic shaping"""
        # retornar uma lista de acoes
        lista_acoes = []
        resp_entrada, lista_remover_entrada = self._ondeAlocarFluxoQoS(porta_entrada, classe, prioridade, banda)

        resp_saida, lista_remover_saida = self._ondeAlocarFluxoQoS(porta_saida, classe, prioridade, banda)

        #nao tem como alocar em uma das portas, entao ja eras -> rejeitar fluxo
        if resp_entrada == SEMBANDA or resp_saida == SEMBANDA: 
            return []

        # remover fluxos que emprestam ou com menor prioridade
        if lista_remover_saida != []:
            # print("remover regras")
            for regra in lista_remover_saida:
                lista_acoes.append(Acao(self,porta_saida, REMOVER, regra))         
        
        # remover fluxos que emprestam ou com menor prioridade
        if lista_remover_entrada != []:
            for regra in lista_remover_saida:
                lista_acoes.append(Acao(self,porta_entrada, REMOVER, regra))
            # print("remover regras")    

        # tem banda na propria classe
        if resp_saida == NAOEMPRESTANDO:
            print("criar regra na propria classe")
            lista_acoes.append(Acao(self, porta_saida, CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, classe, self.getQueueId(classe, prioridade), "flow_label", "actions", False)))
            return lista_acoes
        
        # tem banda na propria classe
        if resp_entrada == NAOEMPRESTANDO:
            # print("criar regra na propria classe")
            lista_acoes.append(Acao(self, porta_entrada, CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, classe, self.getQueueId(classe, prioridade), "flow_label", "actions", False)))
            return lista_acoes
        
        # nao tem banda na propria classe, mas pode emprestar
        if resp_saida == EMPRESTANDO:
            # print("criar regra na outra classe")
            lista_acoes.append(Acao(self, porta_saida, CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, classe, self.getQueueId(classe, prioridade), "flow_label", "actions", True)))
            return lista_acoes
        
        # nao tem banda na propria classe, mas pode emprestar
        if resp_entrada == EMPRESTANDO:
            print("criar regra na outra classe")
            lista_acoes.append(Acao(self, porta_entrada, CRIAR, Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, classe, self.getQueueId(classe, prioridade), "flow_label", "actions", True)))
            return lista_acoes
        
        #algum erro ocorreu -> rejeitar
        return []

    def _ondeAlocarFluxoQoS(self, porta_nome:int, classe:int, prioridade:int, banda:int) -> tuple[int, list[Regra]]:
        """Retorna se o fluxo deve ser armazenado emprestando banda ou nao, e a lista de regras que se deve remover para aloca-lo"""

        porta_obj = self.getPorta(porta_nome)

        # tiver banda na mesma classe -> retornar que apenas criar a regra
        bandaDisponivelPropriaClasse, bandaDisponivelOutraClasse = porta_obj.getBandaDisponivelQoS()
        if banda <= bandaDisponivelPropriaClasse: #Total - usado > banda necessaria
            return NAOEMPRESTANDO, []

        # nao tiver banda mas tiver fluxos emprestando o suficiente -> retornar que deve remover esses fluxos e entao criar a regra
        emprestando = porta_obj.getRegrasEmprestandoAteBandaNecessaria(classe, banda)
        if emprestando != []:
            return NAOEMPRESTANDO, emprestando

        # nao tiver fluxos emprestando mas existir fluxos de menor prioridade na classe -> retornar que deve remover esses fluxos e entao criar a regra
        regrasMenorPrioridade = porta_obj.getLowerPriorityRulesAteBandaNecessaria(classe, prioridade, banda)                
        if regrasMenorPrioridade != []:
            return NAOEMPRESTANDO, regrasMenorPrioridade

        # nao tiver fluxos de menor prioridade mas tiver banda na outra classe para emprestar -> retornar que deve criar a regra na outra classe
        if banda <= bandaDisponivelOutraClasse:
            return EMPRESTANDO, []

        return SEMBANDA, [] # rejeitar 

    def agruparNovaRegraFluxo(self, ip_ver:int, ip_src:str, ip_dst:str):
        return 

    def _backboneGBAM(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, banda:int, prioridade:int, classe:int):

        # alocar banda para um fluxo em um switch sem reservar banda, apenas utilizando os freds, podendo até emprestar banda
        lista_acoes = []

        porta_entrada_obj = self.getPorta(porta_entrada)


        # buscar as regras (freds) expirados
        lista_regras_expiradas = getRegrasExpiradas(porta_entrada_obj.getRegrasBE() + porta_entrada_obj.getRegrasC1() + porta_entrada_obj.getRegrasC2())

        for regra in lista_regras_expiradas:
            self.delRegra(regra.ip_ver, regra.ip_src, regra.ip_dst, regra.src_port,regra.dst_port, regra.proto, regra.porta_entrada, False)
            self.delRegra(regra.ip_ver, regra.ip_src, regra.ip_dst, regra.src_port,regra.dst_port, regra.proto, regra.porta_saida, True)

        # verificar onde se pode alocar o fluxo
        resp_entrada, lista_remover_entrada = self._ondeAlocarFluxoQoS(porta_entrada, classe, prioridade, banda)

        resp_saida, lista_remover_saida = self._ondeAlocarFluxoQoS(porta_saida, classe, prioridade, banda)  
        
        # remover o que for necessario
        # remover fluxos que emprestam ou com menor prioridade
        if lista_remover_saida != []:
            # print("remover regras")
            for regra in lista_remover_saida:
                lista_acoes.append(Acao(self,porta_saida, REMOVER, regra))         
        
        # remover fluxos que emprestam ou com menor prioridade
        if lista_remover_entrada != []:
            for regra in lista_remover_saida:
                lista_acoes.append(Acao(self,porta_entrada, REMOVER, regra))
            # print("remover regras")  

        # criar a regra para backboneGBAM
        self.agruparNovaRegraFluxo(ip_ver, ip_src, ip_dst)

        return

    def getFreeBandwForQoS(self, in_port, classe, prioridade, banda):
        # verifica banda disponível -> retorna 0 se for na própria classe, 1 se for emprestando e -1 se for rejeitado
        
        banda_classe1,banda_classe2 = self.getPorta(in_port).getBandaDisponivelQoS()
        
        if classe == 1:
            if banda_classe1 >= banda:
                return 0
            elif banda_classe2 >= banda:
                return 1
        elif classe ==2 :
            if banda_classe1 >= banda:
                return 1
            elif banda_classe2 >= banda:
                return 0
        return -1
    

    def delRegraGBAM(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida, classe, prioridade, banda):
        """ Parametro:
        ip_ver:str
        ip_src:str
        ip_dst:str
        src_port:str
        dst_port:str
        proto:str
        porta_saida: str
        classe: str
        prioridade: str
        banda: str
        """

        #tem que remover por tupla: ip_src, ip_dst, porta_src, porta_dst, proto
        porta_saida_obj = self.getPorta(porta_saida)

        #obtenho a classe onde a regra estava (1 ou 2, -1 == falha)  
        classe_removida = porta_saida_obj.delRegra(ip_ver=ip_ver, ip_src= ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto)

        #estava emprestando -- na verdade nessa implementacao nao faz diferenca pois estou pesquisando em todas as filas (ok eh ruim, mas por agora fica assim)
        # if classe_removida != classe:

        if(classe_removida>0):
            # tos_aux = CPT[(str(classe_removida), str(prioridade), str(banda))] 
            self.delRegraT(ip_ver=ip_ver, ip_src=ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto,tos = int(tos),tabela= ALL_TABLES)
            print("[S%s]regra removida - ip_src:%s, ip_dst:%s, proto:%s, src_port:%s, dst_port:%s, tos:%s\n" % (self.nome,ip_src,ip_dst,proto, src_port, dst_port, tos))
            return True
        else:
            print("[S%s]regra NAO removida - ip_src:%s, ip_dst:%s, proto:%s, src_port:%s, dst_port:%s, tos:%s\n" % (self.nome,ip_src,ip_dst,proto, src_port, dst_port, tos))
        return False
    
    #adicionar rotas no switch - por agora fica com o nome de rede
    def addRedeIPv4(self, ip_dst, porta): 
        print("[S%s]Rede adicionada %s: %s" % (self.nome, ip_dst, str(porta)))
        self.redes[ip_dst]=porta
        return

    def addMac(self, mac, porta):
        self.macs[mac]=porta
        return

        #retorna uma porta ou -1
    def conheceMac(self, mac):
        if mac in self.macs:
            return self.macs[mac]
        
        return -1

    def addHost(self, ip, porta):
        self.hosts[ip]=porta
        return

#aqui verificar os prefixos
    def getPortaSaida(self, ip_dst):
        #retorna int

        if ip_dst in self.redes:
            return self.redes[ip_dst]

        return None

    def delRede(self, ip_dst, porta):
        #print("[%s]Rede deletada %s: %s" % (self.nome, ip_dst, porta))
        return

    def getPortas(self) -> list[Porta]:
        return self.portas
    
    def getDP(self):
        return self.datapath
    

    def listarRegras(self):
        for porta1 in self.getPortas():
            # return
            print("\n[s%s-p%s] listar regras || C1T:%d, C1U:%d || C2T:%d, C2U: %d ||:\n" % (self.nome,porta1.nome, porta1.c1T, porta1.c1U, porta1.c2T, porta1.c2U))
            for rp1c1 in porta1.getRegrasAltaPrio(SC_REAL):
                print(rp1c1.toString()+"\n")
            #print("\n -- C1P2 (qtdregras: %d):" % (este_switch.p2c1rules.length))
            for rp2c1 in porta1.getRegrasMediaPrio(SC_REAL):
                print(rp2c1.toString()+"\n")
            #print("\n -- C1P3 (qtdregras: %d):" % (este_switch.p3c1rules.length))
            for rp3c1 in porta1.getRegrasBaixaPrio(SC_REAL):
                print(rp3c1.toString()+"\n")
            #print(" -- C2P1 (qtdregras: %d):" % (este_switch.p1c2rules.length))
            for rp1c2 in porta1.getRegrasAltaPrio(SC_NONREAL):
                print(rp1c2.toString()+"\n")
            #print("\n -- C2P2 (qtdregras: %d):" % (este_switch.p2c2rules.length))
            for rp2c2 in porta1.getRegrasMediaPrio(SC_NONREAL):
                print(rp2c2.toString()+"\n")
            #print("\n -- C2P3 (qtdregras: %d):" % (este_switch.p3c2rules.length))
            for rp3c2 in porta1.getRegrasBaixaPrio(SC_NONREAL):
                print(rp3c2.toString()+"\n")


 
