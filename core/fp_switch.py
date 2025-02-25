from fp_acao import Acao
from fp_porta import Porta
from fp_constants import CPT, ALL_TABLES, CRIAR, REMOVER, FORWARD_TABLE, CLASSIFICATION_TABLE, ANY_PORT, NO_METER, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT, BE_HARD_TIMEOUT, BE_IDLE_TIMEOUT, SEMBANDA
from fp_constants import FILA_C1P1, FILA_C1P2, FILA_C1P3, FILA_C2P1, FILA_C2P2, FILA_C2P3, FILA_BESTEFFORT, FILA_CONTROLE, NO_QOS_MARK, class_prio_to_queue_id, SC_REAL, SC_NONREAL, SC_BEST_EFFORT, SC_CONTROL
from fp_regra import Regra
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


    def addRegraQoS(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, flow_label:int, banda:int, prioridade:int, classe:int, fila:int, emprestando:bool):

        # verificar se tem banda o suficiente -> se nao tiver, lancar uma excessao
        if self.getFreeBandwForQoS(porta_entrada,classe, prioridade, banda) == SEMBANDA:
            print("[addregraqos]Sem banda suficiete para alocar Regra: porta entrada")
            return False
        
        if self.getFreeBandwForQoS(porta_saida,classe, prioridade, banda) == SEMBANDA:
            print("[addregraqos]Sem banda suficiete para alocar Regra: porta saida")
            return False

    #adiciona uma regra, na porta entrada e saida, criar meter

        meter_id = generateMeterId(self)
        addRegraM(self, banda, meter_id)

        #armazenar meter
        self.meter_dict[str(ip_ver)+ip_src+ip_dst+str(src_port)+str(dst_port)+str(proto)] = meter_id
        
        self.getPorta(porta_saida).addRegra(Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, meter_id, banda, prioridade, classe, fila, flow_label, '{"qos_mark":%d, "out_port":%d, "meter_id":%d}' %(NO_QOS_MARK, porta_saida, meter_id), emprestando))
        self.getPorta(porta_entrada).addRegra(Regra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_METER, banda, prioridade, classe, fila, flow_label, '{"qos_mark":%d, "out_port":%d, "meter_id":%d}' %(NO_QOS_MARK, porta_saida, meter_id), emprestando))

        addRegraF(self, ip_ver, ip_src, ip_dst, porta_saida, src_port, dst_port, proto, fila, meter_id, NO_QOS_MARK, QOS_IDLE_TIMEOUT, QOS_HARD_TIMEOUT)
        # addRegraF(porta_saida)

        return True
    
    def delRegra(self,ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_saida:int):
    #remove uma regra

        meter_id = getMeterID_from_Flow(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)

        if meter_id != NO_METER: # qos 
            delRegraM(meter_id)
            delMeter(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)

        self.getPorta(porta_saida).delRegra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto)
        delRegraF(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto)

        return True



    def getRegrasEmprestandoAteBandaNecessaria(self, porta_nome:int, classe:int, bandaNecessaria:int):
        emprestando = []
        bandaE = 0

        #sim: somar os fluxos que estao emprestando e ver se a banda eh suficiente para alocar este fluxo 
        porta_obj = self.getPorta(porta_nome)

        bandaDisponivelReal, bandaDisponivelNaoReal = porta_obj.getBandaDisponivelQoS()
        bandaDisponivel = 0
        if classe == SC_REAL:
            bandaDisponivel = bandaDisponivelReal
            emprestando = porta_obj.getRegrasC1Emprestando()
        else:
            bandaDisponivel = bandaDisponivelNaoReal
            emprestando = porta_obj.getRegrasC2Emprestando()

        contadorE = 0
        for i in emprestando:
            bandaE += i.banda
            contadorE+=1

            if bandaDisponivel + bandaE >= bandaNecessaria:
                break
        if bandaE + bandaDisponivel < bandaNecessaria:
            return []

        return emprestando[:contadorE]

#porta_switch antes era dport -> eh a porta onde a regra vai ser salva -> porta de saida do switch
    def alocarGBAM(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_entrada:int, porta_saida:int, banda:int, prioridade:int, classe:int):
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

        # verificar se e
        print("[alocarGBAM-S%s] porta %s, src: %s, dst: %s, banda: %d, prioridade: %d, classe: %d \n" % (self.nome, str(porta_saida), ip_src, ip_dst,banda, prioridade, classe))

        #caso seja classe de controle ou best-effort, nao tem BAM, mas precisa criar regras da mesma forma
        #best-effort
        if classe == SC_BEST_EFFORT:
            return self.addRegraBE(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_saida)

        #controle
        if classe == SC_CONTROL:
            addRegraF(switch=self, qos_mark=NO_QOS_MARK, prioridade=100, hard_timeout=BE_HARD_TIMEOUT, idle_timeout=BE_IDLE_TIMEOUT, flow_removed=False, ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst,ip_dscp= 61, out_port=porta_saida, src_port=src_port, dst_port=dst_port, proto=proto, fila=FILA_CONTROLE,meter_id=None,flag=0)
            
            return True

        # fazer porta entrada e depois porta de saida
    def _alocarGBAM_porta(self, ip_ver:int, ip_src:str, ip_dst:str, src_port:int, dst_port:int, proto:int, porta_considerada:int, banda:int, prioridade:int, classe:int):

        porta_obj = self.getPorta(porta_considerada)
                
        lista_acoes = []
        bandaDisponivelPropriaClasse, bandaDisponivelOutraClasse = porta_obj.getBandaDisponivelQoS()
        
        #para generalizar o metodo GBAM e nao ter de repetir codigo testando para uma classe e depois para outra
        outraClasse = SC_NONREAL
        if classe == SC_NONREAL:
            outraClasse= SC_REAL
            aux = bandaDisponivelPropriaClasse
            bandaDisponivelPropriaClasse = bandaDisponivelOutraClasse
            bandaDisponivelOutraClasse = aux

        # regra ja existe? remover e adicionar nova
        self.delRegra(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_considerada)
        
        #testando na classe original
        if banda <= bandaDisponivelPropriaClasse: #Total - usado > banda necessaria
            
            #nova acao: criar regra: ip_src: origem, ip_dst: destino, porta de saida: nomePorta, tos: tos, banda:banda, prioridade:prioridade, classe:classe, emprestando: nao
            return self.addRegraQoS(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_considerada, NO_QOS_MARK, banda, prioridade, classe, self.getQueueId(classe, prioridade), False)

            
        else: #nao ha banda suficiente 
            #verificar se existe fluxo emprestando largura = verificar se alguma regra nas filas da classe esta emprestando banda
            emprestando = []
            bandaE = 0

            #sim: somar os fluxos que estao emprestando e ver se a banda eh suficiente para alocar este fluxo 

            for i in Porta.getRules(porta_obj, classe, 1):
                if i.emprestando:
                    emprestando.append(i)

            for i in Porta.getRules(porta_obj, classe, 2):
                if i.emprestando:
                    emprestando.append(i)

            for i in Porta.getRules(porta_obj, classe, 3):
                if i.emprestando:
                    emprestando.append(i)

            contadorE = 0
            for i in emprestando:
                bandaE += int(i.banda)
                contadorE+=1

                if cT - cU + bandaE >= int(banda):
                    break
            
            #se as regras que estao emprestando representam largura de banda suficiente para que removendo-as, posso alocar o novo fluxo, entao:
            if cT - cU + bandaE >= int(banda):
                for i in range(contadorE): #criando as acoes para remover as regras que estao emprestando
                    
                    self.delRegra(emprestando[i].ip_ver, emprestando[i].ip_src, emprestando[i].ip_dst, emprestando[i].src_port, emprestando[i].dst_port, emprestando[i].proto, emprestando[i].porta_saida, emprestando[i].porta_entrada)
                    
                #criando a acao  para criar a regra do fluxo, depois de remover as regras selecionadas que emprestam.
                return self.addRegraQoS(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_QOS_MARK, banda, prioridade, classe, self.getQueueId(classe, prioridade), False)
            
            else:       #nao: testa o nao
                #nao: ver se na outra classe existe espaco para o fluxo
                #remover os fluxos que foram adicionados em emprestando
                #emprestando.clear()

                #banda usada e total na outra classe
                cOU, cOT = Porta.getUT(porta_obj, outraClasse)
                if int(banda) <= cOT - cOU:

                    # # # # # salvo com o tos original mas na fila que empresto # # # # #
                    acoes.append( Acao(self.controller.getSwitchByName(self.nome), porta_saida, CRIAR, Regra(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,proto=proto, porta_saida=porta_saida,tos=tos,banda=banda,prioridade=prioridade,classe=outraClasse,emprestando=1)))   
                    self.addRegraQoS(ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, NO_QOS_MARK, banda, prioridade, outraClasse, self.getQueueId(outraClasse, prioridade), True)                    
                    return acoes

                else:
                        #nao: verificar na classe original se nao existem fluxos de menor prioridade que somados dao minha banda
                        
                    bandaP = 0
                    remover = []

                    #sim: remove eles e aloca este
                    if prioridade > 1:
    
                        for i in Porta.getRules(porta_obj, classe, 1):
                            bandaP += int(i.banda)
                            remover.append(i)

                            if cT - cU + bandaP >= int(banda):
                                break
                        
                    if prioridade > 2:
                        if cT - cU + bandaP < int(banda):
                            for i in Porta.getRules(porta_obj, classe, 2):
                                bandaP += int(i.banda)
                                remover.append(i)

                                if cT - cU + bandaP >= int(banda):
                                    break

                    if cT - cU + bandaP >= int(banda):
                        for i in remover:
                            acoes.append( Acao(self.controller.getSwitchByName(self.nome), porta_saida, REMOVER, Regra(ip_ver=i.ip_ver, ip_src=i.ip_src,ip_dst=i.ip_dst,proto=i.proto, porta_saida=porta_saida,tos=i.tos,banda=i.banda,prioridade=i.prioridade,classe=i.classe,emprestando=i.emprestando)))   
                
                        #adiciona na classe original
                        tos = CPT[(str(classe), str(prioridade), str(banda))] #obter do vetor CPT - sei a classe a prioridade e a banda = tos
                        
                        acoes.append( Acao(self.controller.getSwitchByName(self.nome), porta_saida, CRIAR, Regra(ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst,src_port=src_port, dst_port=dst_port, proto=proto, porta_saida=porta_saida,tos=tos,banda=banda,prioridade=prioridade,classe=classe,emprestando=0)))   
                        
                        return acoes

                    else:

                        #nao: rejeita o fluxo - criando uma regra de drop por uns 5segundos
                        print("[alocaGBMA]fluxo descartado\n")
                        #FAZER NADA - se nao tiver regra, o pacote eh dropado automaticamente.
                        return acoes

        #algum erro ocorreu 
        return acoes

    def backboneGBAM(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, porta_entrada, porta_saida, banda, prioridade, classe):
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

        tos = CPT[(classe, prioridade, banda)] 

        #obtenho a classe onde a regra estava (1 ou 2, -1 == falha)  
        classe_removida = porta_saida_obj.delRegra(ip_ver=ip_ver, ip_src= ip_src, ip_dst=ip_dst, src_port=src_port, dst_port=dst_port, proto=proto, tos=tos)

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

    def getPortas(self):
        return self.portas
    
    def getDP(self):
        return self.datapath
    

    def listarRegras(self):
        for porta1 in self.getPortas():
            # return
            print("\n[s%s-p%s] listar regras || C1T:%d, C1U:%d || C2T:%d, C2U: %d ||:\n" % (self.nome,porta1.nome, porta1.c1T, porta1.c1U, porta1.c2T, porta1.c2U))
            for rp1c1 in porta1.p1c1rules:
                print(rp1c1.toString()+"\n")
            #print("\n -- C1P2 (qtdregras: %d):" % (este_switch.p2c1rules.length))
            for rp2c1 in porta1.p2c1rules:
                print(rp2c1.toString()+"\n")
            #print("\n -- C1P3 (qtdregras: %d):" % (este_switch.p3c1rules.length))
            for rp3c1 in porta1.p3c1rules:
                print(rp3c1.toString()+"\n")
            #print(" -- C2P1 (qtdregras: %d):" % (este_switch.p1c2rules.length))
            for rp1c2 in porta1.p1c2rules:
                print(rp1c2.toString()+"\n")
            #print("\n -- C2P2 (qtdregras: %d):" % (este_switch.p2c2rules.length))
            for rp2c2 in porta1.p2c2rules:
                print(rp2c2.toString()+"\n")
            #print("\n -- C2P3 (qtdregras: %d):" % (este_switch.p3c2rules.length))
            for rp3c2 in porta1.p3c2rules:
                print(rp3c2.toString()+"\n")


 
