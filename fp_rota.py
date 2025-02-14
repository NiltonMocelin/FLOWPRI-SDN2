class Rota_Node:
    def __init__(self, switch_name, in_port, out_port):
        self.switch_name = switch_name
        self.in_port = in_port
        self.out_port = out_port

class Rota:
    def __init__(self, ip_ver, src_prefix, dst_prefix, src_port,
                dst_port, proto, rota_nodes):

        self.src_prefix = src_prefix
        self.dst_prefix = dst_prefix
        self.ip_ver= ip_ver
        self.rota_nodes = rota_nodes # (nome_switch (str), porta_saida (int))
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

