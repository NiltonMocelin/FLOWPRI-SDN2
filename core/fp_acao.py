from fp_constants import CRIAR, CPF, ALL_TABLES, REMOVER

#classe para modelar uma acao - remover ou criar regra
#nome switch - (str) identificar qual switch
#porta - (int) identificar a porta do switch
#codigo - (int) identificar a acao 0-CRIAR, 1-REMOVER
#regra - (Regra) uma regra - com as informacoes suficientes para criar ou remover a regra
class Acao:
    def __init__(self, switch_obj, porta, codigo, regra):
        """
        switch_obj : SwitchOVS
        porta : int
        codigo : int
        regra: Regra
        """

        self.switch_obj=switch_obj
        self.porta = porta #int
        self.codigo = codigo
        self.regra=regra
    
    def getRegra(self):
        return self.regra
    #regra = [ip_src, ip_dst, porta_dst, tos, banda, prioridade, classe, emprestando]
    def executar(self):
        print(self.toString())
        if(self.codigo == CRIAR):

            porta = self.switch_obj.getPorta(self.porta)
            
            #criando a regra no vetor
            #### aqui ta errado arrumar 
            porta.addRegra(self.regra.ip_ver, self.regra.ip_src, self.regra.ip_dst, self.regra.proto, self.regra.banda, self.regra.prioridade, self.regra.classe, self.regra.tos, self.regra.emprestando, self.regra.porta_dst)
            
            fila = CPF[(self.regra.classe,self.regra.prioridade)] #com o tos obter a fila = classe + prioridade
            
            #criando id unico
            meter_id = int(self.regra.ip_src.split(".")[3] + self.regra.ip_dst.split(".")[3]) #com a banda obter o meter               
            self.switch_obj.addRegraM(meter_id, int(self.regra.banda))
            print("criando regra meter: meter_id: %d, banda = %s\n" % (meter_id, str(self.regra.banda)))

            #criando a regra na tabela do switch ovs
            self.switch_obj.addRegraF(self.regra.ip_ver, self.regra.ip_src, self.regra.ip_dst, self.regra.tos, self.regra.porta_dst, fila, meter_id, 1)
            
            self.switch_obj.listarRegras()
        else:

            #codigo == REMOVER
            porta = self.switch_obj.getPorta(self.porta)
                        
            #removendo a regra no vetor
            # delRegra(self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, tos):
            porta.delRegra(self.regra.ip_ver, self.regra.ip_src, self.regra.ip_dst, self.regra.src_port, self.regra.dst_port, self.regra.proto, self.regra.tos)

            #removendo a regra da tabela
            # self, ip_ver, ip_src, ip_dst, src_port, dst_port, proto, ip_dscp, tabela=ALL_TABLES):
            self.switch_obj.delRegraT(self.regra.ip_ver, self.regra.ip_src, self.regra.ip_dst, self.regra.src_port, self.regra.dst_port, self.regra.tos ,ALL_TABLES) #remove a regra no ovswitch

            self.switch_obj.delRegraM(meter_id)

            self.switch_obj.listarRegras()

            #porta.delRegra(emprestando[i].ip_src, emprestando[i].ip_dst, emprestando[i].tos) #remove a regra da classe switch
            #self.delRegraT(emprestando[i].ip_src, emprestando.ip_dst, emprestando[i].tos,FORWARD_TABLE) #remove a regra no ovswitch
        return 0
    
    def toString(self):
        if(self.codigo == REMOVER):
            return "[Acao] Remover: " + self.regra.toString() +"\n"
        return "[Acao] Criar: " + self.regra.toString()+"\n"
