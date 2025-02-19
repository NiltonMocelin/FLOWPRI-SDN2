from fp_acao import Acao
from fp_porta import Porta
from fp_constants import CPT, ALL_TABLES, CRIAR, REMOVER, FORWARD_TABLE, CLASSIFICATION_TABLE
from fp_regra import Regra
import sys



from ryu.lib.packet import ether_types, in_proto

class SwitchOVS:
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


        self.meter_dict = {}

    def addPorta(self, nomePorta, larguraBanda, proximoSwitch):
        print("[S%s] Nova porta: porta=%s, banda=%s, proximoSalto=%s\n" % (str(self.nome), str(nomePorta), str(larguraBanda), str(proximoSwitch)))
        #criar a porta no switch
        self.portas.append(Porta(nomePorta, int(larguraBanda), int(int(larguraBanda)*.33), int(int(larguraBanda)*.35), 0, 0, int(proximoSwitch)))

    def delPorta(self, nomePorta):
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
            self.delRegraT(regra.ip_ver, regra.ip_src, regra.ip_dst, regra.src_port, regra.dst_port, regra.proto, regra.tos)
        
        self.portas.pop(index)
        return 


    def getPorta(self, nomePorta):

        for i in self.portas:
            # %s x %s\n" % (i.nome, nomePorta))
            if str(i.nome) == str(nomePorta):
                return i
        #print("[getPorta] porta inexistente: %s\n" % (nomePorta))
        return None
    
    def getPortas(self):
        return self.portas

#porta_switch antes era dport -> eh a porta onde a regra vai ser salva -> porta de saida do switch
    def alocarGBAM(self, ip_ver, ip_src, ip_dst, src_port, dst_port,  proto, porta_saida, banda, prioridade, classe):
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

        banda = int(banda)
        prioridade = int(prioridade)
        classe = int(classe)

        #armazenar as acoes a serem tomadas
        acoes = []

        porta_obj = self.getPorta(str(porta_saida))
 
        print("[alocarGBAM-S%s] porta %s, src: %s, dst: %s, banda: %d, prioridade: %d, classe: %d \n" % (self.nome, str(porta_saida), ip_src, ip_dst,banda, prioridade, classe))

        #caso seja classe de controle ou best-effort, nao tem BAM, mas precisa criar regras da mesma forma
        #best-effort
        if classe == 3:
            self.addRegraF(ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst, ip_dscp=60, out_port=porta_saida, src_port=src_port, dst_port=dst_port, proto=proto, fila=6,meter_id=None,flag=0, hardtime=10)   
            return acoes

        #controle
        if classe == 4:
            self.addRegraF(ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst,ip_dscp= 61, out_port=porta_saida, src_port=src_port, dst_port=dst_port, proto=proto, fila=7,meter_id=None,flag=0)
            
            return acoes

        #para generalizar o metodo GBAM e nao ter de repetir codigo testando para uma classe e depois para outra
        outraClasse = 1
        if classe == 1:
            outraClasse=2

        #banda usada e total na classe original
        cU, cT = Porta.getUT(porta_obj, classe)

        # print("[antes de alocar] banda usada: %d, banda total: %d \n" % ( cU, cT)) 

        ### antes de alocar o novo fluxo, verificar se ja nao existe uma regra para este fluxo -- caso exista remover e adicionar de novo? ou so nao alocar?
        #a principio - remover e alocar de novo
        # self.delRegraGBAM(self, origem, destino, porta, str(classe), str(prioridade), str(banda))
        # correto eh utilizar Acoes -- e evitar criar regras repetidas (que removem e criam a mesma)
        # se GBAM falhar, as acoes nao ocorrem !!
        acoes.append( Acao(self.controller.getSwitchByName(self.nome), porta_saida, REMOVER, Regra(ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst,src_port=src_port, dst_port=dst_port, porta_saida=porta_saida,tos=tos,banda=banda,prioridade=prioridade,classe=classe,emprestando=0)))   

        #testando na classe original
        if int(banda) <= cT - cU: #Total - usado > banda necessaria
            #criar a regra com o TOS = (banda + classe)
            #regra: origem, destino, TOS ?
            tos = CPT[(str(classe), str(prioridade), str(banda))] #obter do vetor CPT - sei a classe a prioridade e a banda = tos

            #nova acao: criar regra: ip_src: origem, ip_dst: destino, porta de saida: nomePorta, tos: tos, banda:banda, prioridade:prioridade, classe:classe, emprestando: nao
            acoes.append( Acao(self.controller.getSwitchByName(self.nome), porta_saida, CRIAR, Regra(ip_ver=ip_ver, ip_src=ip_src,ip_dst=ip_dst,src_port=src_port, dst_port=dst_port, proto=proto, porta_saida=porta_saida,tos=tos,banda=banda,prioridade=prioridade,classe=classe,emprestando=0)))   

            return acoes #retornando as acoes

        else: #nao ha banda suficiente 
            #verificar se existe fluxo emprestando largura = verificar se alguma regra nas filas da classe esta emprestando banda
            emprestando = []
            bandaE = 0

            #sim: somar os fluxos que estao emprestando e ver se a banda eh suficiente para alocar este fluxo 

            for i in Porta.getRules(porta_obj, classe, 1):
                if i.emprestando == 1:
                    emprestando.append(i)

            for i in Porta.getRules(porta_obj, classe, 2):
                if i.emprestando ==1:
                    emprestando.append(i)

            for i in Porta.getRules(porta_obj, classe, 3):
                if i.emprestando ==1:
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
                    
                    acoes.append( Acao(self.controller.getSwitchByName(self.nome), porta_saida, REMOVER, Regra(ip_ver=emprestando[i].ip_ver, ip_src=emprestando[i].ip_src,ip_dst=emprestando[i].ip_dst,src_port=emprestando[i].src_port, dst_port=emprestando[i].dst_port, proto=emprestando[i].proto,porta_saida=emprestando[i].porta_saida,tos=emprestando[i].tos,banda=emprestando[i].banda,prioridade=emprestando[i].prioridade,classe=emprestando[i].classe,emprestando=emprestando[i].emprestando)))   
                
                tos = CPT[(str(classe), str(prioridade), str(banda))] #obter do vetor CPT - sei a classe a prioridade e a banda = tos
                
                #criando a acao  para criar a regra do fluxo, depois de remover as regras selecionadas que emprestam.
                acoes.append( Acao(self.controller.getSwitchByName(self.nome), porta_saida, CRIAR, Regra(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,src_port=src_port, dst_port=dst_port, proto=proto,porta_saida=porta_saida,tos=tos,banda=banda,prioridade=prioridade,classe=classe,emprestando=0)))   
                return acoes
                
            else:       #nao: testa o nao
                #nao: ver se na outra classe existe espaco para o fluxo
                #remover os fluxos que foram adicionados em emprestando
                #emprestando.clear()

                #banda usada e total na outra classe
                cOU, cOT = Porta.getUT(porta_obj, outraClasse)
                if int(banda) <= cOT - cOU:

                    #calcular o tos - neste switch o fluxo o tos permanece o mesmo, a regra eh criada no vetor da classe que empresta mas no switch deve ser criada na classe original - isso pode pois todas as filas compartilham da mesma banda e sao limitadas com o controlador
                    tos = CPT[(str(classe), str(prioridade), str(banda))] #novo tos equivalente
                    
                    #sim: alocar este fluxo - emprestando = 1 na classe em que empresta - na fila correspondente
                    
                    # # # # # salvo com o tos original mas na fila que empresto # # # # #
                    acoes.append( Acao(self.controller.getSwitchByName(self.nome), porta_saida, CRIAR, Regra(ip_ver=ip_ver,ip_src=ip_src,ip_dst=ip_dst,proto=proto, porta_saida=porta_saida,tos=tos,banda=banda,prioridade=prioridade,classe=outraClasse,emprestando=1)))   
                    
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

    def getFreeBandwForQoS(self, in_port, out_port, classe, prioridade, banda):
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
    
    def criarRegraBE(self):

        

        return
    
    # def criarRegraQoS(self):
    #     return

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

    #criar uma mensagem para remover uma regra de fluxo no ovsswitch
    def delRegraT(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, ip_dscp, tabela=ALL_TABLES):
        """ Parametros:
        ip_ver:str
        ip_src:str
        ip_dst:str
        src_port:str
        dst_port:str
        proto:str
        ip_dscp:int
        tabela=ALL_TABLES
        """

        #tabela = 255 = ofproto.OFPTT_ALL = todas as tabelas
        #print("Deletando regra - ipsrc: %s, ipdst: %s, tos: %d, tabela: %d\n" % (ip_src, ip_dst, tos, tabela))
        #tendo o datapath eh possivel criar pacotes de comando para o switch/datapath
        #caso precise simplificar, pode chamar o cmd e fazer tudo via ovs-ofctl

        #modelo com ovs-ofctl:
        #we can remove all or individual flows from the switch
        # sudo ovs-ofctl del-flows <expression>
        # ex. sudo ovs-ofctl del-flows dp0 dl_type=0x800
        # ex. sudo ovs-ofctl del-flows dp0 in_port=1
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #remover a regra meter associada
        meter_id = int(ip_src.split(".")[3] + ip_dst.split(".")[3])                
        self.delRegraM(meter_id)
                        
        if(ip_dscp != None):
            ip_dscp = '000000'
        
        #generico ipv4
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_dscp=ip_dscp)
 
        if ip_ver == 'ipv6':
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ipv6_src=ip_src, ipv6_dst=ip_dst, ip_dscp=ip_dscp)

        #tratamento especial para este tipo de trafego
        if proto ==in_proto.IPPROTO_TCP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, tcp_src = src_port, tcp_dst=dst_port,ip_dscp=ip_dscp)

            if ip_ver == 'ipv6':
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ip_proto = proto, ipv6_src=ip_src, ipv6_dst=ip_dst, tcp_src = src_port, tcp_dst=dst_port,ip_dscp=ip_dscp)

        elif proto == in_proto.IPPROTO_UDP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, udp_src = src_port, udp_dst=dst_port,ip_dscp=ip_dscp)
            if ip_ver == 'ipv6':
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ip_proto = proto, ipv6_src=ip_src, ipv6_dst=ip_dst, udp_src = src_port, udp_dst=dst_port,ip_dscp=ip_dscp)

        mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, match=match, table_id=tabela, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

        ##esse funciona - remove tudo
        #mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, table_id=ofproto.OFPTT_ALL, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
 
        datapath.send_msg(mod)

        return 0
    
    

#Injetar pacote no controlador com instrucoes - serve para injetar pacotes que foram encaminhado por packet_in (se nao eles sao perdidos)
    def injetarPacote(self, datapath, fila, out_port, packet):
        actions = [datapath.ofproto_parser.OFPActionSetQueue(fila), datapath.ofproto_parser.OFPActionOutput(out_port)] 
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=100,
            actions=actions,
            data=packet.data)
        
        datapath.send_msg(out)

#add regra tabela FORWARD
    def addRegraF(self, ip_ver, ip_src, ip_dst, ip_dscp, out_port, src_port, dst_port, proto, fila, meter_id, flag, hardtime=None):
        """ Parametros:
        ip_ver:str
        ip_src: str
        ip_dst: str
        ip_dscp: int
        out_port: int
        src_port: int
        dst_port: int 
        proto: str
        fila: int
        meter_id: int 
        flag: int
        hardtime=None
        """

        #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
# hardtimeout = 5 segundos # isso eh para evitar problemas com pacotes que sao marcados como best-effort por um contrato nao ter chego a tempo. Assim vou garantir que daqui 5s o controlador possa identifica-lo. PROBLEMA: fluxos geralmente nao duram 5s, mas eh uma abordagem.
        
        #Para que a regra emita um evento de flow removed, ela precisa carregar uma flag, adicionada no OFPFlowMod
        #flags=ofproto.OFPFF_SEND_FLOW_REM
        
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        idletime = 30 # 0 = nao limita
        #hardtime = None

        prioridade = 100
       
        #match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,ipv4_src=ip_src, ipv4_dst=ip_dst,ip_dscp=ip_dscp)
        # match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ip_src, ipv4_dst=ip_dst)
        
        #caso queiramos que seja generico
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ip_src, ipv4_dst=ip_dst)
        
        if ip_ver == 'ipv6':
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6,ipv6_src=ip_src, ipv6_dst=ip_dst)

        if(ip_dscp != None):
            ip_dscp = '000000'
        
        #tratamento especial para este tipo de trafego
        if proto ==in_proto.IPPROTO_TCP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, tcp_src = src_port, tcp_dst=dst_port,ip_dscp=ip_dscp)
        elif proto == in_proto.IPPROTO_UDP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, udp_src = src_port, udp_dst=dst_port,ip_dscp=ip_dscp)


        actions = [parser.OFPActionSetQueue(fila), parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] # essa instrucao eh necessaria?
 
###nao esta funcionando 
        if meter_id != None:
            inst.append(parser.OFPInstructionMeter(meter_id=meter_id))
#            inst = [parser.OFPInstructionMeter(meter_id,ofproto.OFPIT_METER), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        #marcar para gerar o evento FlowRemoved
        if flag == 1:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE, flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)
            return

        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE)

        if hardtime != None:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, hard_timeout = hardtime, priority=prioridade, match=match, instructions=inst, table_id=FORWARD_TABLE)

        datapath.send_msg(mod)
        
#add regra tabela CLASSIFICATION
#se o destino for um ip de controlador, 
    def addRegraC(self, ip_ver ,ip_src, ip_dst, src_port, dst_port, proto, ip_dscp):
        """ parametros:
        ip_ver: str
        ip_src: str
        ip_dst: str
        src_port: str
        dst_port: str
        proto: str
        ip_dscp: str
        """

        #https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html#flow-instruction-structures
         #criar regra na tabela de marcacao - obs - utilizar idletime para que a regra suma - serve para que em switches que nao sao de borda essa regra nao exista
                         #obs: cada switch passa por um processo de enviar um packet_in para o controlador quando um fluxo novo chega,assim, com o mecanismo de GBAM, pode ser que pacotes de determinados fluxos sejam marcados com TOS diferentes da classe original, devido ao emprestimo, assim, em cada switch o pacote pode ter uma marcacao - mas com essa regra abaixo, os switches que possuem marcacao diferentes vao manter a regra de remarcacao. Caso ela expire e cheguem novos pacotes, ocorrera novo packet in e o controlador ira executar um novo GBAM - que vai criar uma nova regra de marcacao
        #print("[criando-regra-tabela-marcacao] ipsrc: %s, ipdst: %s, tos: %d\n" % (ip_src, ip_dst, ip_dscp))

        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #generico       
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)

        #tratamento especial para este tipo de trafego
        if proto ==in_proto.IPPROTO_TCP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, tcp_src = src_port, tcp_dst=dst_port,ip_dscp=ip_dscp)
            if ip_ver == 'ipv6':
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6, ip_proto = proto, ipv6_src=ip_src, ipv6_dst=ip_dst, tcp_src = src_port, tcp_dst=dst_port,ip_dscp=ip_dscp)

        elif proto == in_proto.IPPROTO_UDP:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv4_src=ip_src, ipv4_dst=ip_dst, udp_src = src_port, udp_dst=dst_port,ip_dscp=ip_dscp)
            if ip_ver == 'ipv6':
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto = proto, ipv6_src=ip_src, ipv6_dst=ip_dst, udp_src = src_port, udp_dst=dst_port,ip_dscp=ip_dscp)

        if ip_dscp == None:
            ip_dscp = '000000'      

        actions = [parser.OFPActionSetField(ip_dscp=ip_dscp)]

        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        idletime = 30 # 30s sem pacotes, some
        prioridade = 100

        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout = idletime, priority=prioridade, match=match, instructions=inst, table_id=CLASSIFICATION_TABLE)
        datapath.send_msg(mod)

    #criando regra meter
    def addRegraM(self, meter_id, banda):
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #criando meter bands
        bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, len_=0, rate=banda, burst_size=10)]#e esse burst_size ajustar?
        req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=bands)
        datapath.send_msg(req)
        return

    def delRegraM(self, meter_id):
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_DELETE, meter_id=meter_id)
        datapath.send_msg(req)
        return

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

