#!/usr/bin/env python

## Consensus: Practical Byzantine Fault Tolerance
#https://gitee.com/bison-fork/sawtooth-pbft/blob/main/tests/test_liveness.yaml#

try:
  import docker
except:
    print("Install docker sdk e docker-compose !!")
    exit(0)

import subprocess
import os

from netifaces import AF_INET, ifaddresses, interfaces

def getInterfaceName():
    interfs=interfaces()
    interfs.remove('lo')
    return interfs[0]


def getBlockchain(src_prefix, dst_prefix, general_name):
  client = docker.from_env()
  lista_containers = client.containers.list(filters={'name':general_name})
  for c in lista_containers:
      if '' in c.name and src_prefix in c.name and dst_prefix in c.name:
          return fromContainerGetPort(c)

    
def fromContainerGetPort(containerDict):
    lista_args = containerDict.attrs['Args']
    for a in lista_args:
        if 'tcp' in a:
            return a.split(':')[1]
    return None

def criar_blockchain(nome_blockchain, endpoint_ip, chave_publica, chave_privada, CONSENSUS_PORT,VALIDATOR_PORT, REST_API_PORT, NETWORK_PORT, PEERS_IP:list=None, chaves_peers:list = None, is_genesis=False) -> str:
  """
  is_genesis: true if genesis, and false if not (default)
  nome_blockchain: blockchain and container name
  chave_publica: sawadm keygen .pub
  chave_privada: sawadm keygen .pub
  chaves_peers: chaves publicas sawadm keygen dos pares (importante para o nó gênesis) (3 max)
  VALIDADOR_IP: validator module ip address
  VALIDADOR_PORT: validator module port
  REST_API_IP: rest_api module ip address
  REST_API_PORT: rest_api module port
  CONSENSUS_IP: consensus module ip address
  CONSENSUS_PORT: consensus module port
  NETWORK_IP: network ip address 
  NETWORK_PORT: network ip address
  PEERS_IP: pbft must be fully peered, if it is the genesis node == None
  Returns: container-id
  """

  print('lista_nos: ', PEERS_IP)

####################### subir container validador ######################
  print("Criar nova blockchain (containers: rest,settings,validador,consenso):")
  print('IS GENESIS: ', is_genesis)

  chave_publica1 = ''
  chave_publica2 = ''
  chave_publica3 = ''

  interfacename = getInterfaceName()


  if is_genesis:
    chave_publica1 = chaves_peers[0]
    chave_publica2 = chaves_peers[1]
    chave_publica3 = chaves_peers[2]

  peers = ''

  for ip in PEERS_IP:
    peers+=' --peers tcp://'+ip

  # campos para substituir:
  # @nm@, @rp@, @np@, @vp@, @cp@

  # ler arquivo correspondente

  # substituir os %s e %d com os valores corretos

  # escrever o arquivo docker-compose.yaml

  file_compose = "host/host_qosblockchain/nao_genesis_blockchain.yaml"

  if is_genesis:
     file_compose = "host/host_qosblockchain/genesis_blockchain.yaml"
  try:
    open_file = open(file_compose, 'r+')

    linhas = open_file.read()

    novas_linhas = linhas.replace("sth", interfacename)
    novas_linhas = novas_linhas.replace("@nm@",nome_blockchain)
    novas_linhas = novas_linhas.replace("@ep@",str(endpoint_ip))
    novas_linhas = novas_linhas.replace("@rp@",str(REST_API_PORT))
    novas_linhas = novas_linhas.replace("@np@",str(NETWORK_PORT))
    novas_linhas = novas_linhas.replace("@vp@",str(VALIDATOR_PORT))
    novas_linhas = novas_linhas.replace("@cp@",str(CONSENSUS_PORT))

    novas_linhas = novas_linhas.replace("@pub@",chave_publica)
    novas_linhas = novas_linhas.replace("@pri@",chave_privada)

    if is_genesis:
      novas_linhas = novas_linhas.replace("@pub1@",chave_publica1)
      novas_linhas = novas_linhas.replace("@pub2@",chave_publica2)
      novas_linhas = novas_linhas.replace("@pub3@",chave_publica3)

    novas_linhas = novas_linhas.replace("@peers@",peers)

    open_file.close()
  except:
     print("ERRO ao modificar arquivo yaml")
     return False

  try:
    docker_compose_file = open("docker-compose.yaml",'w+')

    docker_compose_file.write(novas_linhas)

    docker_compose_file.close()
  except:
    print("Erro ao escrever o docker-compose.yaml file")
    return False

  # executar o docker-compose
  print(subprocess.run(["sudo", "docker-compose", "up", "-d"]))

  # observar se todos foram executados ou se deu erro

  return True