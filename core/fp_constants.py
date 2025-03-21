from netifaces import AF_INET, ifaddresses, interfaces

# chamei de constants mas tem diversas variáveis aqui ....

#controller singleton
controller_singleton = None

# algumas variaveis para o controlador
arpList = {}

freds = []

# dict para controlar as meter rules dos switches id_switch + _ + 5-tupla = id_meter :X
meter_ids = {}

#self.mac_to_port = {} arrumar esses dois, tirar do controlador e trzer para ca
#self.ip_to_mac = {}

#vetor com os enderecos ip dos controladores conhecidos (enviaram icmps)
controladores_conhecidos = []

switches = [] #switches administrados pelo controlador
# rotas_ipv4 = {} # ip_dst/prefix:mask :list[switch_name]
# rotas_ipv6 = {} # ip_dst/prefix:mask :list[switch_name]



IP_MANAGEMENT_HOST = "192.168.0.1" # alterar isso
PORTA_MANAGEMENT_HOST_SERVER = 9090

#Listar interfaces disponiveis
# print(interfaces())

#cada controlador deve ter o seu
# CONTROLLER_INTERFACE = "eth0"
CONTROLLER_INTERFACE = "enp7s0"

CONTROLADOR_ID = "No-id"
IPCv4 = None 
IPCv6 = None 
IPCc = None

BAIXA_PRIO=3
MEDIA_PRIO=2
ALTA_PRIO=1

MACC = None


PORTAC_H = 4444 #porta para receber contratos de hosts
PORTAC_C = 8888 #porta para receber contratos de controladores
PORTAC_X = 9999 #porta para receber arquivos de configuracao json do administrador
PORTAC_ICMP15 = 1115
PORTAC_ICMP16 = 1116

## Interface web
PORTA_WEBS_RCV = 9971 #porta websocket para solicitacoes de informacoes JSON para a interface WEB
PORTA_WEBS_SND = 9972 #porta websocket paraenviar informacoes JSON para a interface WEB
PORTA_ACCESS_WEB = 8080 #porta para acessar a pagina web

websocket_conn = None

IPV4_CODE = 0x0800
IPV6_CODE = 0x86DD
ICMPV4 = '1'
ICMPV6 = '58'
TCP = 6
UDP = 17
EGP = 8
IGP = 9

QOS_HARD_TIMEOUT  = 5
QOS_IDLE_TIMEOUT  = 2
MONITORING_TIMEOUT= 2
BE_HARD_TIMEOUT  = 5
BE_IDLE_TIMEOUT   = 2

#service classes
SC_REAL        = 1
SC_NONREAL     = 2
SC_BEST_EFFORT = 3
SC_CONTROL     = 4

MARCACAO_MONITORAMENTO = 0x7 # 7 decimal 
QTD_MONITORAMENTO      = 20

ANY_PORT= -1
NO_METER = -1
NO_IDLE_TIMEOUT = 0
NO_HARD_TIMEOUT = 0
NO_QOS_MARK = -1

OFP_NO_BUFFER = 0xffffffff

FILA_C1P1=0
FILA_C1P2=1
FILA_C1P3=2
FILA_C2P1=3
FILA_C2P2=4
FILA_C2P3=5
FILA_BESTEFFORT=6
FILA_CONTROLE=7

#codigos das acoes
CRIAR=0
REMOVER=1
EMPRESTANDO=1
NAOEMPRESTANDO=0
SEMBANDA = -1

CLASSIFICATION_TABLE = 0 #tabela para marcacao de pacotes
FORWARD_TABLE = 1 #tabela para encaminhar a porta destino
ALL_TABLES = 255 #codigo para informar que uma acao deve ser tomada em todas as tabelas

CPT = {} #chave (CLASSE,PRIORIDADE,BANDA): valor TOS  
CPF = {} #classe + prioridade = fila


#fila + banda = tos

# aqui é 5-tupla:list[(pacote,timestamp)]
fluxos_classificacao_dict = {}

dhcp_msg_type_code = {
            1: 'DHCP_DISCOVER',
            2: 'DHCP_OFFER',
            3: 'DHCP_REQUEST',
            4: 'DHCP_DECLINE',
            5: 'DHCP_ACK',
            6: 'DHCP_NAK',
            7: 'DHCP_RELEASE',
            8: 'DHCP_INFORM',
 }


class_prio_to_queue_id = {
            11: 0,
            12: 1,
            13: 2,
            21: 3,
            22: 4,
            23: 5,
            3: 6,
            4: 7
 }