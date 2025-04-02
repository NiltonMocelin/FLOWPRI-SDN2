# Teste funcionalidade filas utilizando v3 (mas o principio é o mesmo para as próximas versões)

* Topologia h1-s1-s2-h4.

* Todos os links com 15mb largura de banda

* Teste para verificar se as filas estão limitando a largura de banda corretamente.

* As regras METER foram desabilitadas.

* Os fluxos apenas estão sendo limitados pela largura de banda reservada para as filas.

* Filas 0,1,2 da CLASSE1(tempo-real) e filas 3,4,5 da CLASSE2(não-tempo-real) podem utilizar até 33% + 35% = 68% da largura de banda total (só emprestam entre elas)

* CLASSE3 (best-effort) fila 6 - pode usar min 25%, max 100%  - se nenhuma outra estiver usando ele empresta o que conseguir.

* CLASSE4 (controle fila 7 - 7% (nao empresta)

* Caso outro teste seja desejado, modificar o arquivo switchQueueConf2teste.sh

* Executar a topologia:

`sudo python topo5_v2.py`

* Abrir Xterm de root1 (c1), root2 (c2), host1 e 2xhost4:

`xterm root1 root2 h1 h4 h4`

* No Xterm de root1, executar o script de criação de filas:

`sh switchQueueConf2teste.sh`

* Iniciar c1teste.py e c2teste.py:

`ryu-manager c1teste.py --ofp-tcp-listen-port 7000`

`ryu-manager c1teste.py --ofp-tcp-listen-port 6699`

###### Verificar se as filas foram criadas:

- listar filas em uma porta de um switch:

` sudo ovs-vsctl list qos`

` sudo ovs-ofctl queue-stats s1`

` sudo ovs-appctl qos/show s1-eth1`

- listar configuracao qdisc de uma interface:

` tc qdisc show`

` tc class show dev s1-eth1`

- limpar todas as configurações de qos anteriores ( limpar antes de rodar uma topologia ):

` ovs-vsctl clear port s1-eth1 qos`

ou

` ovs-vsctl --all destroy qos `

###### Testar se elas estao limitando conforme definidas no script:

* Xterm host1 e criar um contrato para enviar dados pela fila 0, <banda> <prioridade> <classe> - fila é uma combinação de prioridade e classe:

`python contrato_cli_v2.py 10.10.10.1 172.16.10.1 172.16.10.4 1000 1 1`

* utilizar iftop em h4 para medir a largura de banda de um fluxo:

`iftop -i <interface>`

* Iniciar um servidor iperf em h4 udp:

`iperf -s`

* Iniciar o cliente iperf em h1 udp e tentar utilizar toda a largura de banda do link (para observar a limitação ocorrendo):

`iperf -b 15M -u -c 172.16.10.4 -t 100`

* testar fila 0:

`sh ovs-ofctl add-flow s1 ip,in_port=1,actions=enqueue:4:0`

`sh ovs-ofctl add-flow s1 ip,in_port=4,actions=enqueue:1:0`

`sh ovs-ofctl add-flow s2 ip,in_port=4,actions=enqueue:1:0`

`sh ovs-ofctl add-flow s2 ip,in_port=1,actions=enqueue:4:0`


* testar fila 1:

`sh ovs-ofctl add-flow s1 ip,in_port=1,actions=enqueue:4:1`

`sh ovs-ofctl add-flow s1 ip,in_port=4,actions=enqueue:1:1`

`sh ovs-ofctl add-flow s2 ip,in_port=4,actions=enqueue:1:1`

`sh ovs-ofctl add-flow s2 ip,in_port=1,actions=enqueue:4:1`

* testar fila 2:

`sh ovs-ofctl add-flow s1 ip,in_port=1,actions=enqueue:4:2`

`sh ovs-ofctl add-flow s1 ip,in_port=4,actions=enqueue:1:2`

`sh ovs-ofctl add-flow s2 ip,in_port=4,actions=enqueue:1:2`

`sh ovs-ofctl add-flow s2 ip,in_port=1,actions=enqueue:4:2`


* testar fila 3:

`sh ovs-ofctl add-flow s1 ip,in_port=1,actions=enqueue:4:3`

`sh ovs-ofctl add-flow s1 ip,in_port=4,actions=enqueue:1:3`

`sh ovs-ofctl add-flow s2 ip,in_port=4,actions=enqueue:1:3`

`sh ovs-ofctl add-flow s2 ip,in_port=1,actions=enqueue:4:3`

* testar fila 4:

`sh ovs-ofctl add-flow s1 ip,in_port=1,actions=enqueue:4:4`

`sh ovs-ofctl add-flow s1 ip,in_port=4,actions=enqueue:1:4`

`sh ovs-ofctl add-flow s2 ip,in_port=4,actions=enqueue:1:4`

`sh ovs-ofctl add-flow s2 ip,in_port=1,actions=enqueue:4:4`

* testar fila 5:

`sh ovs-ofctl add-flow s1 ip,in_port=1,actions=enqueue:4:5`

`sh ovs-ofctl add-flow s1 ip,in_port=4,actions=enqueue:1:5`

`sh ovs-ofctl add-flow s2 ip,in_port=4,actions=enqueue:1:5`

`sh ovs-ofctl add-flow s2 ip,in_port=1,actions=enqueue:4:5`

* testar fila 6:
`sh ovs-ofctl add-flow s1 ip,in_port=1,actions=enqueue:4:6`

`sh ovs-ofctl add-flow s1 ip,in_port=4,actions=enqueue:1:6`

`sh ovs-ofctl add-flow s2 ip,in_port=4,actions=enqueue:1:6`

`sh ovs-ofctl add-flow s2 ip,in_port=1,actions=enqueue:4:6`

* testar fila 7:

`sh ovs-ofctl add-flow s1 ip,in_port=1,actions=enqueue:4:7`

`sh ovs-ofctl add-flow s1 ip,in_port=4,actions=enqueue:1:7`

`sh ovs-ofctl add-flow s2 ip,in_port=4,actions=enqueue:1:7`

`sh ovs-ofctl add-flow s2 ip,in_port=1,actions=enqueue:4:7`


### Conclusões:

* [IPERF-UDP] por algum motivo o link de 15Mbps só suporta 12.8. Mas o de 30Mbps funcionam +- 30Mbps

* [IPERF-TCP] bem mais preciso - fila de 10Mbps fornecendo os 10Mbps

* A topologia coloca delay e perda tanto nas configuracoes tc root dos hosts quando das bridges (ovs)

* As filas não são criadas apenas utilizando o comando : sudo ovs-vsctl -- set port s1-eth4 qos...

* Para criar as filas, de fato, é necessário remover a fila root criada pela topologia (algo como):

`sudo tc qdisc del dev s1-eth1 root`

* O comando clear qos do ovs-vsctl apenas remove as entradas da tabela do ovsdb aparentemente (tem lacunas que não compreendi):

`sudo ovs-vsctl clear port s1-eth1 qos`

* Para simular as condições dos links assim como pretendido com configurações definidas na topologia (delay, loss ...) - usar TC-NETEM:

- [tutorial netem](https://www.cs.unm.edu/~crandall/netsfall13/TCtutorial.pdf)

- This causes the added delay to be 100ms ± 10ms with the next random element depending 25% on the last one. This isn't true statistical correlation, but an approximation.

`sudo tc qdisc add dev s1-eth1 root netem delay 100ms 10ms 25%`