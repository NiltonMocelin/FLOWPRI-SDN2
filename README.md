# obs RYU:

Link Profile Cloudlab : https://www.cloudlab.us/p/flowprisdn/teste03

* explicar o que precisa ser configurado nesse experimento - quase tudo ja se configura com os scripts que rodam sozinhos


# Componentes principais

* QoSBlockchain

* Flow Monitoring

* Flow Classification

* QoS Multi-domínio

* GBAM

* Agrupamento de fluxos -> Conjunction

* Para testar, utilize o materia em experimentos-NETNS

* QoSBLockchain não está 100% integrada... (problemas inerentes ao tipo de ambiente virtual proporcionado por NETNS)


<!-- <!-- <!-- {
*Virou tudo estático, não vou fazer automático* <--- { Configurar a criação das portas e switches no fp_topology_discovery -- configurar o addporta lá
* Descobrir com quem cada porta dos switches se conecta. -- verificar como o topology discovery do ryu faz isso e implementar tbm}

* Dar uma olhada no que precisa implementar para o suporte de ipv6
* Implementar uma GUI bonita e com estatísticas

* Testar no cloudlab
* Definir cenários para testes.
* Implementar controladores e comparar QoS
* Escrever Artigo
* Escrever Plano Aula
* Escrever Plano Dissertação
}


-> interface web ta com problema

-> implementar a parte gui

-> implementar configuração servidor addhost ip_ver, ip_host, switch, in_port, para poder identificar os hosts do domínio e o controlador saber quem é do seu domínio -> entender roteamento em ipv6 pra ter ctz


## Refatorando 

# Funcionalidades a implementar

 * Burlar NAT: Identificador único para fluxos baseado em conteúdo de pacote -> IPv6 é o jeito mais fácil e rápido!!

 * Substituir esse DSCP por um classificador --- sei la como que vamos fazer isso agora

 * Implementar a descoberta de domínios na rota que utilizam flowpri. (considerando que a rota é estática durante o tráfego do fluxo)

 * Implementar a garantia de QoS -- monitar? ....

 * Implementar o servidor third-party que vai coordenar o QoS as a service. -- todos os controladores da rota precisam informar que fazem da rota e que estao fornecendo qos pra o fluxo devidamente identificado com um identificador unico.  

 * Aplicacao no host informando QoS dos seus fluxos

 * Suporte a redes virtuais --- por último.... -->

## QoSBlockchain:

* Atente-se ao local das chaves criadas /sawtooth_keys/ e "/"+username+"/.sawtooth/keys/"

* Para acessar (ler), as chaves precisam ser chmod 755

* A API criada para o qosblockchain ainda nao esta 100%


* Para enviar transações na mão: python3.8 main_qos_cli.py reg_qos --url http://0.0.0.0:13655 2048_6_172.16.2.30_172.16.1.30_42912_5001 '{"action":"reg_qos", "flow_name":"2048_6_172.16.2.30_172.16.1.30_42912_5001", "qosregisters": [{"nodename": "172.16.1.10", "route_nodes": [{"ordem": 1, "nome_peer": "172.16.2.10", "chave_publica": "03724d8dff744fc5caa33a7c4f8eca29b8d37601b197a763f7d3d363672817f1b1", "nro_saltos": 1}, {"ordem": 2, "nome_peer": "172.16.1.10", "chave_publica": "03724d8dff744fc5caa33a7c4f8eca29b8d37601b197a763f7d3d363672817f1b1", "nro_saltos": 1}], "blockchain_nodes": [], "state": 1, "service_label": 1, "application_label": "video", "req_bandwidth": 2000, "req_delay": 1, "req_loss": 10, "req_jitter": 0, "bandwidth": 1514, "delay": 0, "loss": 1, "jitter": 0}]}'

* Porém, provavelmente está tendo algum erro no transaction processor - quando tiver tempo arrumo...



## DHCPv6

- IPv6 Neighbor Discovery Protocol defines 5 types of messages that use ICMPv6 encapsulation:

    Router Solicitation (ICMPv6 type 133)
    Router Advertisement (ICMPv6 type 134)
    Neighbor Solicitation (ICMPv6 type 135)
    Neighbor Advertisement (ICMPv6 type 136)
    Redirect Message (ICMPv6 type 137)

- Existe 3 modos: SLAAC (stateless E default for clients); Stateful; Manual

- Focamos em SLAAC

- Em SLAAC, os clientes declaram seu próprio IP

- Isso é feito utilizando o protocolo NDP (Neighbour discovery protocol)

- Os clients também podem enviar mensagens RS (Router Solicitation) e recebem um RA (Router Advertisement)

- implementar IPv6 no ryu{
    - ipv6 icmpv6: https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_icmpv6.html?highlight=icmpv6
    - implementação github: https://github.com/faucetsdn/faucet/commit/054871dc19fa5c21086fe9be93a60b4b15c718cd
    - (base das funcoes) outra implementação: https://github.com/faucetsdn/faucet/blob/main/faucet/valve_packet.py
     - nao entendi, tem alguma coisa que renomearam ryu para os-ken: https://opendev.org/openstack/os-ken/src/branch/master/os_ken
}

### Ideias antigas - talvez futuramente (não urgente)

* Configurar a criação das portas e switches no fp_topology_discovery -- configurar o addporta lá
* Descobrir com quem cada porta dos switches se conecta. -- verificar como o topology discovery do ryu faz isso e implementar tbm


* ! foi implementado dhcp == funcionando --> mas precisa mudar para que uma classe rede agrupe os switches participantes + a informacao host(mac+ip) deve ser armazenada com os switches, para saber onde os hosts estao (no caso de cenários sem movimento de hosts)


* poderia propor uma forma de simular filas utilizando meter rules
{
    * poderia controlar divisoes de banda para cada classe utilizando regras meter para emprestar banda entre as classes prioritárias - da forma como ja se faz, praticamente

    * E o best-effort, que seria a problemática neste caso, poderia se criar uma regra meter-group do tamanho da classe, e agrupar os fluxos que utilizariam a mesma meter (pq se duas regras utilizam a mesma meter ==> utilizam a mesma partição-mesmo contador)

    * Em casos onde nao se pode configurar -> poderia se fazer dessa forma

}


* Poderia ter um servidor intermediario para a parte de descoberta de serviços utilizando o esquema de contratos. Apenas para IPv6
* Quando um contrato chega em um domínio, este contrato deve subir ao servidor regional
* quando um pacote chega em um domínio, este deve enviar um icmp inf request para o servidor regional, solicitando um contrato, se existir! (melhor que pedir ao domínio de origem, pois o fluxo pode ser encaminhado por outra rota!!!)

-> implemetar bgp e a parte de roteamento dinamico

-> criar a versão com trocas de contratos utilizando um servidor terceiro (regional como falei)
-> comparar as versoes em termos de atraso
-> escrever artigo!


####

#### Conjunctions

##### Como usar conjunctions:
    refs: <a href="https://manpages.ubuntu.com/manpages/focal/en/man7/ovs-fields.7.html">Referencia conjunctions</a>
    <a href="https://ryu.readthedocs.io/en/latest/nicira_ext_ref.html?highlight=nxactionconjunction#ryu.ofproto.ofproto_v1_3_parser.NXActionConjunction">Referencia conjunctions do ryu</a>


    # a regra conjunction possui a descricao da conjunção na acao e os valores do conjunto são colocados no match, como outra regra qualquer.
    
    # cada regra conjunction possui um valor do conjunto, e então a descrição da conjunção diz quantas clausulas devem ser avaliadas,a ordem de analise e o id da conjunction.
    
    # não se pode ter ações de encaminhamento, mas pode ter de remarcação

    # ENTão, numa regra de encaminhamento, se pode ter match com apenas uma conjunction (pelo que entendi e pelo que se pode fazer)
    
    # porem, como as conjunctions podem ter varias ações (varios campos de match com varios valores, que se combinam como OU), pode se montar 
    
    # diversas listas de valores para os campos de match, apenas utilizando os ids e numero de clausula.

    # Obs: no match, o primeiro campo deve ser conj_id (de outra forma não funcionou, talvez eu tenha errado)

    
    ## Criando uma conjunction:

    match=parser.OFPMatch(qq coisa)

    actions=[parser.NXActionConjunction(clause=nro, n_clauses=qtd_clauses,id_=unico_int)] --> nao pode ter encaminhamento aqui
    
    criar openflow mod [...]

    ## Conectando uma conjunction a uma regra de encaminhamento:
    match=parser.OFPMatch(conj_id=nro_id_conjunction,...)  --> coloque primeiro a conj_id, depois os outros campos
    actions=[qq coisa]

    dictiona = {'conj_id':10, 'eth_type':0x0800}
    Pode passar dicionarios para parser.OFPMatch(**dictiona)

    Pode criar na mao:
    sudo ovs-ofctl add-flow switch1 ip,ip_proto=6,tcp_dst=80,actions:=conjunction\(1234,2/2\)

    sudo ovs-ofctl add-flow switch1 conj_id=10,ip,ip_proto=6,tcp_dst=80,actions:outport=2

 ### OBS sobre as conjunctions:
    As primeiras vezes que rodei, funcionou normal
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src='172.16.1.1')
        actions = [parser.NXActionConjunction(clause=1,n_clauses=2, id_=222)]
        self.add_flow2(datapath, 0, match, actions)

        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst='172.16.1.1')
        actions = [parser.NXActionConjunction(clause=2,n_clauses=2, id_=222)]
        self.add_flow2(datapath, 0, match, actions)


        POREM, QUANDO FUI TESTAR EM UM OUTRO MOMENTO, O NUMERO DA CLAUSE=1 ERA INCREMENTADO +1 NO MOMENTO DE SUBIR AS CONJUNCTIONS, LOGO A PRIMEIRA ERA CRIADA COMO CLAUSE=2 N_CLAUSES=2 E A SEGUNDA TBM (N SEI PQ, MAS DEVE LIMITAR NO N_CLAUSES). ENTAO A SEGUNDA SUBSTITUIA A PRIMEIRA E FICAVA APENAS UMA... DEMOREI HORAS PARA IDENTIFICAR :D

        Essa é a maneira correta :
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src='172.16.1.1')
        actions = [parser.NXActionConjunction(clause=0,n_clauses=2, id_=1111)]
        self.add_flow2(datapath, 0, match, actions)
        # self.del_flow(datapath, match)     

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,tcp_dst=2300)
        actions = [parser.NXActionConjunction(clause=1,n_clauses=2,id_=1111)]
        # self.del_flow(datapath, match)        
        self.add_flow2(datapath, 0, match, actions)

    * Obs 2 (IMPORTANTE):
    Outra coisa importante sobre as conjunctions:
    O header (que usa a conjunction no match) e as conjunctions (que usam no action) precisam ter a mesma prioridade quando sao criadas == ou nao funcionam, são tratadas como conjunções diferentes

#### Se estiver tendo problemas para remover regras com o RYU
    
    ## o OFPFlowMod(ofproto.OFPFC_DELETE..) não deleta

    ## Tente especificar out_port e out_group parameter, ai ele remove

    ## desse jeito: datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, table_id=ofproto.OFPTT_ALL, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)

    ## se ainda não estiver removerndo, lembre-se de que alguns campos possuem dependencias, como ipv4_src depende de eth_type=0x0800 !


### Sobre Controladores SDN e simuladores de rede:

- Em um momento, pensei em tirar o atraso dos enlaces para isolar o tempo de sobrecarga da aplicação para apenas o tempo de processamento.

- Isso foi uma péssima ideia. Os bufferes do controlador recebiam muitos pacotes, pois o atraso da placa de rede era praticamente 0.5ms (menor que o tempo de processamento).

- Com isso, mesmo otimizando o controlador, muitos pacotes eram perdidos.

- Por isso, settei os enlaces com 10ms de atraso (5ms em cada VETH).

- Desta forma, o controlador tem tempo de tratar os pacotes - não elimina a possibiliade de ter perda de pacotes caso o buffer volte a encher, no entanto, não vai ocorrer como quando o atraso era instantaneo.

- para isso: `sudo tc qdisc add dev veth38 root netem delay 10ms`