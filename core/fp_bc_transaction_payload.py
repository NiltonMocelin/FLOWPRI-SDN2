import json
class QoSRegister:
    #medida de QoS
    def __init__(self, nodename:str, route_nodes:list[str], blockchain_nodes:list[str], state:int, service_label:int, application_label:int, req_bandwidth:int, req_delay:int, req_loss:int, req_jitter:int, bandwidth:int, delay:int, loss:int, jitter:int):  
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
    def __init__(self, ip_src, ip_dst, ip_ver, src_port:str, dst_port:str, proto:str, qosregisters:list[QoSRegister]):
        self.name:str = ip_src+'_'+ip_dst +'_'+ str(ip_ver) +'_'+ str(src_port) +'_'+str(dst_port) +'_'+ str(proto)
        self.qosregisters:list[QoSRegister] = qosregisters # class QoS # lista de registros de qos para um fluxo

    def toString(self):
        flow_json = {"name": self.name, "qosregisters":[qosreg.toString() for qosreg in self.qosregisters]}
        return json.dumps(flow_json)
    