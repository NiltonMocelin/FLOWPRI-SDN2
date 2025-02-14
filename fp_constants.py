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

## mudou:-: {} ip_dst: [rota_nodes]
rotas = {}


KEYS_LOCATION = '/sawtooth_keys/'

CHAVE_PUBLICA_SAWADM = ""
CHAVE_PRIVADA_SAWADM = ""

# 5-tupla: [{"timestamp": "timestamp", "tamanho": "tamanho"}]
fluxos_monitorados = {}

IP_MANAGEMENT_HOST = "192.168.0.1" # alterar isso
PORTA_MANAGEMENT_HOST_SERVER = 9090

#Listar interfaces disponiveis
# print(interfaces())

#cada controlador deve ter o seu
CONTROLLER_INTERFACE = "eth0"

CONTROLADOR_ID = str(CONTROLLER_INTERFACE)
IPCv4 = str(ifaddresses(CONTROLLER_INTERFACE)[AF_INET][0]['addr'])
IPCv6 = str(ifaddresses(CONTROLLER_INTERFACE)[10][0]['addr'].split("%")[0])

MACC = str(ifaddresses(CONTROLLER_INTERFACE)[17][0]['addr'])

print("Controlador ID - {}".format(CONTROLADOR_ID))
print("Controlador IP - {}".format(IPCv6))
print("Controlador MAC - {}".format(MACC))

PORTAC_H = 4444 #porta para receber contratos de hosts
PORTAC_C = 8888 #porta para receber contratos de controladores
PORTAC_X = 9999 #porta para receber arquivos de configuracao json do administrador
PORTAC_ICMP15 = 1115
PORTAC_ICMP16 = 1116

## Interface web
PORTA_WEBS_RCV = 9971 #porta websocket para solicitacoes de informacoes JSON para a interface WEB
PORTA_WEBS_SND = 9972 #porta websocket paraenviar informacoes JSON para a interface WEB
PORTA_ACCESS_WEB = 9970 #porta para acessar a pagina web

websocket_conn = None

IPV4 = '4'
IPV6 = '41'
ICMPV4 = '1'
ICMPV6 = '58'
TCP = '6'
UDP = '17'
EGP = '8'
IGP = '9'

#service classes
SC_REAL = 1
SC_NONREAL = 2
SC_BEST_EFFORT = 3
SC_CONTROL = 4

MARCACAO_MONITORAMENTO = 252 # 11111100 -- primeiros 6 dscp, ultimos 2  -> 6+2 = tos

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

CLASSIFICATION_TABLE = 0 #tabela para marcacao de pacotes
FORWARD_TABLE = 1 #tabela para encaminhar a porta destino
ALL_TABLES = 255 #codigo para informar que uma acao deve ser tomada em todas as tabelas

CPT = {} #chave (CLASSE,PRIORIDADE,BANDA): valor TOS  
CPF = {} #classe + prioridade = fila

blockchain_table = {}
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
