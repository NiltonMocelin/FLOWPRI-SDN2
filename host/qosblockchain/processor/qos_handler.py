# Copyright 2016-2018 Intel Corporation
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
# ------------------------------------------------------------------------------

#base sawtooth-sdk/examples/xo_python

import logging

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError

from qos_payload import QoSPayload
from qos_state import QOS_NAMESPACE, QoSState, Flow, fromJsonToFlow

import json

LOGGER = logging.getLogger(__name__)

class QoSTransactionHandler(TransactionHandler):
    # Disable invalid-overridden-method. The sawtooth-sdk expects these to be
    # properties.
    # pylint: disable=invalid-overridden-method

    @property
    def family_name(self):
        return 'qos'

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [QOS_NAMESPACE]
                
    def apply(self, transaction, context):

        print("[Inicio] transacao")
        header = transaction.header
        signer = header.signer_public_key

        qos_payload = QoSPayload.from_bytes(transaction.payload)

        print('header ', header, '; signer ', signer, '; ',qos_payload)

        print('flow_str: ', str(qos_payload.flow_str))

        flow_json = qos_payload.flow_str
        flow:Flow = fromJsonToFlow(flow_json)

        print("FLOW to string: ", flow.toString())

        action = qos_payload.action
        flow_name = qos_payload.flow_name

        qos_state = QoSState(context)

        if action == 'reg_qos':
            
            if flow_json == None:
                print("nenhum fluxo foi informado!")
                return
            print('registrando qos')

            qos_state.reg_qos(flow_name, flow)
        else:
            raise InvalidTransaction('Invalid action')

        # if action == 'show':
        #     print('recuperando um fluxo')
        #     flow_recuperado = qos_state.get_qos(flow_name)
        #     _display(flow=flow_recuperado)

        # if action == 'list':
        #     print('recuperando todos os fluxos')
        #     ## arrumar
        #     flow_recuperado = qos_state.get_qos(flow_name)
        #     _display(flow=flow_recuperado)
        
        print("[Fim] transacao")
    

def _display(flow:Flow):
    # pylint: disable=logging-not-lazy
    LOGGER.debug(flow.toString())
    