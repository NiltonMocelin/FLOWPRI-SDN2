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

from sawtooth_sdk.processor.exceptions import InvalidTransaction
import json

class QoSPayload:

    def __init__(self, payload):
        try:
            # The payload is csv utf-8 encoded string
            
            # pensar nas informacoes a serem armazenadas
            #goal_classe, goal_app, goal_service, goal_bandwidth, goal_latency, 
            #
            print(payload.decode())
            print("QoSPayload printed")

            payload_json = json.loads(payload.decode())

            print("QoSPayload payload_json")

            action = payload_json["action"]
            flow_name = payload_json["flow_name"]
            flow_str = payload_json["flow"]

            print("QoSPayload loaded")
        # aqui
        except ValueError as e:
            raise InvalidTransaction("Invalid payload serialization") from e

        if not action:
            raise InvalidTransaction('Action is required')

        if (action == 'reg_qos' or action == 'del_qos') and not (flow_str or flow_name):
            raise InvalidTransaction('Flow is required')
        
        elif action == 'show' and not flow_name:
            raise InvalidTransaction('Flow name is required')

        if action == '':

            try:
                print('a')
            except ValueError:
                raise InvalidTransaction('Error') from ValueError

        print("QoSPayload saiu")

        self._action = action
        self._flow_str = flow_str
        self._flow_name = flow_name
        
    @staticmethod
    def from_bytes(payload):
        return QoSPayload(payload=payload)

    @property
    def action(self):
        return self._action
    @property
    def flow_name(self):
        return self._flow_name
    @property
    def flow_str(self):
        return self._flow_str