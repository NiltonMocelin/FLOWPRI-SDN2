# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------

import hashlib

from sawtooth_sdk.processor.exceptions import InternalError
import json

#ledger para a comunicação entre AS A e AS B
QOS_NAMESPACE = hashlib.sha512('qos'.encode("utf-8")).hexdigest()[0:6]


# transacao = {
#     'acao':'funcao',
#     'flow':{flow}
# }


def _make_qos_address(name):
    return QOS_NAMESPACE + \
        hashlib.sha512(name.encode('utf-8')).hexdigest()[:64]

# class EndPairQoS: ## IDEIA: apenas registrar QoS quando perceber mudança significativa de classe ou qos de um fluxo
#     def __init__(self, endpair_name:str, ip_src:str):
#         # interpretando o XO game (jogo da velha)
#         # Isso representa o estado atual do fluxo, ou seja, o resultado das ações informadas nos blocos ( lá cada transação era um movimento e aqui se montava o tabuleiro, o estado do jogo e os jogadores)
#         self.endpair_name:str = endpair_name
#         self.ip_src:str = ip_src
#         self.ip_dst:str = ''
#         self.ip_ver:str = ''

#         self.flows: list[Flow] = [] # lista de fluxos de um par

#     def addFlow(self, flow):
#         self.flows.append(flow)
#         return True
    
#     def remFlow(self, name):
#         for f in self.flows:
#             if f.name == name:
#                 self.flows.remove(f)
#                 return True
#         return False
    
#     def toString(self):

#         #####        
#         flows_json_str = ""
#         for flow in self.flows:
#             flows_json_str+= ',' + flow.toString()
#         flows_json_str = flows_json_str.replace(',','',1)# tem outros jeitos, depois mudar
#         #####

#         json_result = "{\"endpair_name\":\"%s\",\
#             \"ip_ver\":\"%s\",\
#             \"ip_src\":\"%s\",\
#             \"ip_dst\":\"%s\",\
#             \"flows\":[%s]\
#         }" % (self.endpair_name, self.ip_ver, self.ip_src, self.ip_dst, flows_json_str)

#         return json_result
    
#     def fromJSON(self, endpair_qos_json):
#         return
    

class Flow:
    # dissecar o FRED aqui
    def __init__(self, name:str, src_port:str, dst_port:str, proto:str, duration:list, qos:list, state:str, freds:list):
        self.name:str = name
        self.src_port:str = src_port
        self.dst_port:str = dst_port
        self.proto:str= proto
        # self.as_duration:list[:str] = ['AS1001:50s'] # duração que cada AS participou do fluxo
        # self.as_list:list[:str] = ['AS1001', 'AS1002'] #text/public key ...
        self.duration:list[:str] = duration
        self.qoss: list[QoS] = qos # class QoS # lista de registros de qos para um fluxo
        self.state:str = state #Going, Stoped
        self.freds:list[Fred] = freds #caso existam freds diferentes, serão armazenados aqui

    def toString(self):

        ####
        freds_json_str = ""
        for fred in self.freds:
            freds_json_str+= ',' + fred.toString()
        freds_json_str= freds_json_str.replace(',','',1)# tem outros jeitos, depois mudar
        ####

        ####
        qos_json_str = ""
        for qos in self.qoss:
            qos_json_str+= ',' + qos.toString()
        qos_json_str = qos_json_str.replace(',','',1)# tem outros jeitos, depois mudar
        ####

        flow_json = "{\"name\":\"%s\",\
            \"state\":\"%s\",\
            \"ip_src\":\"\",\
            \"ip_dst\":\"\",\
            \"src_port\":\"%s\",\
            \"dst_port\":\"%s\",\
            \"proto\":\"%s\",\
            \"qos\":[%s],\
            \"freds\":[%s]}" % (self.name, self.state, self.src_port, self.dst_port, self.proto, qos_json_str, freds_json_str)
        
        return flow_json
    

# organizar isso depois, pois o fred já possui muitas das informacoes do Flow (menos a parte das métricas de QoS)
class Fred:
    def __init__(self, nao_sei:str):
        self.nao_sei:str = nao_sei
    
    def toString(self):
        fred_json = "{\
        \"nao_sei\":\"%s\"}" % (self.nao_sei)

        return fred_json

class QoS:
    #medida de QoS
    def __init__(self, bandwidth:str):
        self.node:str = 'a' #nó que calculou
        self.bandwidth:str = bandwidth

    def toString(self):
        qos_json = "{\
        \"bandwidth\":\"%s\"\
        \"fred_id\":\"1\" \
        }" % (self.bandwidth)

        return qos_json
class QoSState:

    TIMEOUT = 3

    def __init__(self, context):
        """Constructor.

        Args:
            context (sawtooth_sdk.processor.context.Context): Access to
                validator state from within the transaction processor.
        """

        self._context = context
        self._address_cache = {}

    # def flow_start(self, endpair_name, flow:Flow):
    #     return
    
    # def flow_end(self, endpair_name, flow:Flow):
    #     return
    
    def reg_qos(self, flow_name, flow:Flow):
        """Register (store) qos of a flow in the validator state.

        Args:
            endpair_name (str): identification name of the end hosts that are communicating (one-way).
            endpair_qos (FlowQoS): The QoS state of a flow.
        """

        ### aqui
        flow_recuperado = self._load_qos(flow_name=flow_name)
        print('flow_recuperado: flowname:', flow_name, ' --> flow:', flow_recuperado)

        flow_existente:Flow = None 
        
        if flow_recuperado!=None:
            flow_existente = fromJsonToFlow(flow_recuperado)

        # se ja existe, entao, adicionar as informacoes do fluxo no existente (eh um update de estado)
        if flow_existente != None:
            
            #adicionar os freds calculados --> deve conter apenas um fred na transação recebida
            for fred in flow.freds:
                flow_existente.freds.append(fred)

            #adicionar os qoss calculados --> deve conter apenas um calculo na transação recebida
            for qos in flow.qoss:
                flow_existente.freds.append(qos)

            #atualizar o estado do fluxo
            flow_existente.state = flow.state
        else:
            flow_existente = flow


        # pegar a lista de qos do fluxo deste par e adicionar o novo
        # a fazer !!
        # endpair_flows[flow.name] = flow #(string)

        self._store_qos(flow_name=flow_name, flow=flow_existente)
        return
    
    def get_qos(self,flow_name):
        """Get the game associated with game_name.

        Args:
            game_name (str): The name.

        Returns:
            (Game): All the information specifying a game.
        """

        return self._load_qos(flow_name=flow_name)#.get(endpair_name)

    ####################################

    def delete_qos(self, flow_name):
        """Delete the Game named game_name from state.

        Args:
            game_name (str): The name.

        Raises:
            KeyError: The Game with game_name does not exist.
        """

        # flow = self._load_qos(flow_name=flow_name)

        
        # del endpair_qos_hist[endpair_name] # como agora é apenas um, mudando acao
        # if endpair_qos_hist: # isso eh para depois, so exclui o qos de um fluxo, tem que codar ainda
        #     self._store_qos(endpair_name, endpair_qos_hist=endpair_qos_hist)
        # else:
        #     self._delete_qos(endpair_name)
        del self._address_cache[flow_name]
        self._delete_qos(flow_name)

    def _store_qos(self, flow_name, flow):
        address = _make_qos_address(flow_name)
        print('_store: flow_name:',flow_name)
        state_data = self._serialize(flow)

        self._address_cache[address] = state_data

        self._context.set_state(
            {address: state_data},
            timeout=self.TIMEOUT)

    def _delete_qos(self, flow_name):
        address = _make_qos_address(flow_name)

        self._context.delete_state(
            [address],
            timeout=self.TIMEOUT)

        self._address_cache[address] = None

    def _load_qos(self, flow_name):
        """A partir de um nome fluxo, recupera-lo"""
        # a ideia eh ser um flow por endereco, mas no XO, em um endereco são armazenados varios games... por isso usa dicionario
        # por enquanto vamos deixar o dicionario, pois não sei como está funcionando exatamente.. (modificar após analise)

        address = _make_qos_address(flow_name)

        if address in self._address_cache:
            if self._address_cache[address]:
                serialized_flow = self._address_cache[address] # em formato json_string_utf-8
                flow = self._deserialize(serialized_flow)
            else:
                flow = None
        else:
            state_entries = self._context.get_state(
                [address],
                timeout=self.TIMEOUT)
            if state_entries:

                self._address_cache[address] = state_entries[0].data # o que tem nas outras posicoes ?
                
                # descobrindo
                for ste in state_entries:
                    print(ste.data)

                flow = self._deserialize(data=state_entries[0].data)

            else:
                self._address_cache[address] = None
                flow = None

        return flow

    def _deserialize(self, data):
        """Take bytes stored in state and deserialize them into Python
        Game objects.

        Args:
            data (bytes): The UTF-8 encoded string stored in state.

        Returns:
            (dict): game name (str) keys, Game values.
        """

        flow = None
        try:
            # for flow in data.decode(): # precisa ver primeiro como vai ficar isso em json ... deixar para depois
            #     # naendpair_qos_histme, board, state, player1, player2 = endpair_qos.split(",")

            #     endpair_qos_hist[endpair_name] = json.loads(endpair_qos_str)
            flow = json.loads(data)
        except ValueError as e:
            raise InternalError("Failed to deserialize flow data") from e

        return flow

    def _serialize(self, flow:Flow):
        """Takes a dict of game objects and serializes them into bytes.

        Args:
            games (dict): game name (str) keys, Game values.

        Returns:
            (bytes): The UTF-8 encoded string stored in state.
        """

        # duvida: usar json ou usar pickle?
        # a principio, json
        
        return flow.toString().encode()



def fromJsonToFlow(json)->Flow:
    f = Flow(name=json['name'], src_port= json['src_port'], dst_port=json['dst_port'], proto=json['proto'], state=json['state'], duration=[], qos=json['qos'], freds=json['freds'])
    return f

#flow = """{"name":"192.168.0.0-192.168.0.1-5000-5000-tcp","state":"Going","src_port":"5000","dst_port":"5000","proto":"tcp","qos":[],"freds":[]}"""