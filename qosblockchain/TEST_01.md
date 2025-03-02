# Guia para teste 01 - 4 validadores - Teste de conectividade e Setup da rede

- Arquitetura básica da rede QoSBlockchain

<img src="../imgs/qosblockchain_arquitetura.png"/>

- Arquitetura da troca de mensagens:

<img src="../imgs/qosblockchain_arquitetura2.png"/>

* VAL 0 é o nó gênesis, que inicia a blockchain com o bloco gênesis. Este nó precisa conhecer todas as chaves publicas dos validadores participantes da rede e os endpoints de cada nó

* Portanto, para testar sem o FLOWPRI-SDN, é necessário executar o server_fred_exchange_pbft.py em modo test. (--test)

* Primeiro, deve executar o server sequencialmente em ordem, VAL 1, VAL 2, VAL 3, adicionando a chave pública criada no nó atual (VAL 1) ao FRED do próximo nó (VAL 2), da mesma forma adicionando o endereço ip:porta no FRED.

* Obs modifique os caminhos se necessário

* O hyperledger sawtooth não envia chaves por conta, é necessário envia-las para o nó gênesis antes de subir a blockchain que controi o bloco gênesis

<hr/>

<h3>VAL 1</h3>

- Rodar servidor: 

    $ sudo $HOME/miniconda3/envs/pyfeatures38/bin/python3.8 -m server_fred_exchange_pbft_docker_compose -M 192.168.0.140 --test

- Enviar FRED para testar a comunicação (o controlador SDN vai utilizar o client para enviar o fred aos hosts finais)

    $ python client_fred_exchange_pbft.py 0.0.0.0 5555 '{"ip_ver":"4",    "proto":"tcp",    "ip_src":"0.0.0.1",    "ip_dst":"192.168.0.2",    "src_port":"9999",    "dst_port":"9988",    "mac_src":"xx",    "mac_dst":"xx",    "prioridade":"1",    "classe":"1",    "bandiwdth":"1",    "loss":"1",    "delay":"1",    "jitter":"1",    "label":"youtube-video-rt",    "blockchain_name":"as1_as2-1",    "AS_src_ip_range":[],    "AS_dst_ip_range":[],    "ip_genesis":"",    "lista_chaves":[],    "lista_nos":[]    }'

- Após cada fred enviado o servidor preenche e printa na tela o novo fred com a chave publica criada. (alterar o blockchain name se for subir outros validadores na mesma máquina - uso para o nome do container) copie o fred no client_fred_exchange_pbft para subir outros containers na mesma máquina

<h5>Caso queira modificar o fred na mão</h5>

- Copie o endereço de rede utilizado no container e o endereço do validador utilizados.

- Adicione esse endereco:porta em lista_nos do fred

- Copie o conteúdo da chave pública criada (sawadm) e adicione em lista_chaves do fred

- O FRED atualizado deve ser utilizado no próximo nó

- Repetir os passos para VAL 2 e VAL 3

<h3>VAL 1 (gênesis)</h3>

- O FRED deve conter 3 chaves em lista_chaves e 3 ip:porta em lista_nos nesta etapa

- O nó se identifica como gênesis se o endereço ip_src do FRED for o mesmo do nó (192.168.0.140 por exemplo).

- Para testar um nó gênesis, modifique o ip_src do FRED para o IP da interface (o mesmo que foi colocado em server_fred_exchange_pbft_docker_compose -M esse-ip)

- Rode o servidor,

- Crie 3 nós com os FREDs preenchios conforme a etapa correspondente

- A blockchain deve subir sem problemas

- Teste de Conectividade completo
