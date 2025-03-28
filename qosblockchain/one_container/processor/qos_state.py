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


# DECIDINDO os valores e tipos de dados das transacoes -> depois ajustar para o controlador tbm


import hashlib

from sawtooth_sdk.processor.exceptions import InternalError
import json

#ledger para a comunicação entre AS A e AS B
QOS_NAMESPACE = hashlib.sha512('qos'.encode("utf-8")).hexdigest()[0:6]


def _make_qos_address(name):
    return QOS_NAMESPACE + \
        hashlib.sha512(name.encode('utf-8')).hexdigest()[:64]

class QoSRegister:
    #medida de QoS
    def __init__(self, nodename:str, route_nodes:list, blockchain_nodes:list, state:int, service_label:int, application_label:int, req_bandwidth:int, req_delay:int, req_loss:int, req_jitter:int, bandwidth:int, delay:int, loss:int, jitter:int):  
        #fred data
        self.nodename:str = nodename #nó que calculou
        self.route_nodes:list[str] = route_nodes
        self.blockchain_nodes:list[str] = blockchain_nodes
        self.state:int = state
        self.service_label:str = service_label
        self.application_label:str = application_label
        self.req_bandwidth:int = req_bandwidth
        self.req_delay:int = req_delay
        self.req_loss:int = req_loss
        self.req_jitter:int = req_jitter
        # qosreg
        self.bandwidth:int = bandwidth
        self.delay:int = delay
        self.loss:int = loss
        self.jitter:int = jitter

    def toString(self):
        qos_json = {"nodename":self.nodename, 
        "route_nodes":self.route_nodes, 
        "blockchain_nodes":self.blockchain_nodes, 
        "state":self.state, 
        "service_label":self.service_label, 
        "application_label":self.application_label, 
        "req_bandwidth":self.req_bandwidth, 
        "req_delay":self.req_delay, 
        "req_loss":self.req_loss, 
        "req_jitter":self.req_jitter, 
        "bandwidth":self.bandwidth, 
        "delay":self.delay, 
        "loss":self.loss,  
        "jitter": self.jitter}

        return json.dumps(qos_json)

class FlowTransacao:
    # dissecar o FRED aqui
    def __init__(self, ip_src, ip_dst, ip_ver, src_port:str, dst_port:str, proto:str, qosregisters:list):
        self.name:str = str(ip_ver) +'_'+ str(proto)+ '_'+  ip_src+'_'+ip_dst +'_'+ str(src_port) +'_'+str(dst_port)
        self.qosregisters:list[QoSRegister] = qosregisters # class QoS # lista de registros de qos para um fluxo

    def toString(self):
        flow_json = {"name": self.name, "qosregisters":[qosreg.toString() for qosreg in self.qosregisters]}
        return json.dumps(flow_json)
    
    
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

    def reg_qos(self, flow_name, flow:FlowTransacao):
        """Register (store) qos of a flow in the validator state.

        Args:
            endpair_name (str): identification name of the end hosts that are communicating (one-way).
            endpair_qos (FlowQoS): The QoS state of a flow.
        """

        ### aqui
        flow_recuperado = self._load_qos(flow_name=flow_name)
        print('flow_recuperado: flowname:', flow_name, ' --> flow:', flow_recuperado)

        flow_existente:FlowTransacao = None 
        
        if flow_recuperado!=None:
            flow_existente = fromJsonToFlow(flow_recuperado)

        # se ja existe, entao, adicionar as informacoes do fluxo no existente (eh um update de estado)
        if flow_existente != None:

            #adicionar os qoss calculados --> deve conter apenas um calculo na transação recebida
            for qos in flow.qosregisters:
                flow_existente.qosregisters.append(qos)
        else:
            flow_existente = flow

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

    def _serialize(self, flow:FlowTransacao):
        """Takes a dict of game objects and serializes them into bytes.

        Args:
            games (dict): game name (str) keys, Game values.

        Returns:
            (bytes): The UTF-8 encoded string stored in state.
        """

        # duvida: usar json ou usar pickle?
        # a principio, json
        
        return flow.toString().encode()



def fromJsonToFlow(json)->FlowTransacao:
    lista_flowfields = json['name'].split("_")
    ip_src = lista_flowfields[0]
    ip_dst = lista_flowfields[1]
    ip_ver = lista_flowfields[2]
    proto = lista_flowfields[3]
    src_port = lista_flowfields[4]
    dst_port = lista_flowfields[5]
    f = FlowTransacao(ip_src=ip_src, ip_dst=ip_dst, ip_ver=ip_ver, src_port=src_port, dst_port=dst_port, proto=proto, qosregister=json['qosregisters'])
    return f