
echo "Running Setup scritp - PRESUPOSTO QUE O REQUIREMENTS.SH FOI EXECUTADO"
echo "Ambiente com 5 domínios" # testando, se rodar tudo certinho, fazer para dois e .. 5


#################################################################################################

echo "configurando dominio 1"
echo "Criando o namespace host dom 1"
sudo ip netns add VRF1

echo "Criando o namespace controller dom 1"
sudo ip netns add VRF2


echo "Listando namespaces"
sudo ip netns list

# qual fica para o host e qual fica para o switch ? o ímpar vai para o "host" e o par para o switch 
echo "Criando as portas veth1 e veth2 ( host dom1 )"
sudo ip link add veth1 type veth peer name veth2

echo "Criando as portas veth3 e veth4 ( controller dom1 )"
sudo ip link add veth3 type veth peer name veth4

echo "Criando as portas veth5 e veth6 ( switch dom1(parent) - controller (vrf) )"
sudo ip link add veth5 type veth peer name veth6

echo "Criando as portas veth7 e veth8 ( switch dom1 - switch dom2 )"
sudo ip link add veth7 type veth peer name veth8

echo "Subindo interfaces"
sudo ifconfig veth1 up # host-switch
sudo ifconfig veth2 up # switch-host 1
sudo ifconfig veth3 up # controller-switch
sudo ifconfig veth4 up # switch-controller 2
sudo ifconfig veth5 up # eth0-switch 
sudo ifconfig veth6 up # switch-eth0 3
sudo ifconfig veth7 up # switch1-switch2 4
sudo ifconfig veth8 up # switch2-switch1

echo "configuring delay 5ms for each interface"
sudo tc qdisc add dev veth1 root netem delay 10ms
sudo tc qdisc add dev veth2 root netem delay 10ms
sudo tc qdisc add dev veth3 root netem delay 10ms
sudo tc qdisc add dev veth4 root netem delay 10ms
sudo tc qdisc add dev veth5 root netem delay 10ms
sudo tc qdisc add dev veth6 root netem delay 10ms
sudo tc qdisc add dev veth7 root netem delay 10ms
sudo tc qdisc add dev veth8 root netem delay 10ms

echo "Movendo as interfaces ímpares para dentro dos namespaces"
sudo ip link set veth1 netns VRF1
sudo ip link set veth3 netns VRF2

echo "Configurando IP e subindo as interfaces dentro do namespace"
sudo ip netns exec VRF1 ifconfig veth1 172.16.1.30/24
sudo ip netns exec VRF2 ifconfig veth3 172.16.1.10/24

echo "configurando interface de acesso ao switch1"
sudo ifconfig veth5 172.16.1.50/24

echo "Subindo os lo (loopback interfaces)"
sudo ip netns exec VRF1 ifconfig lo up
sudo ip netns exec VRF2 ifconfig lo up

echo "Configurando o switch do domínio 1"
sudo ovs-vsctl add-br switch1

sudo ovs-vsctl add-port switch1 veth2 -- set interface veth2 ofport_request=1
sudo ovs-vsctl add-port switch1 veth4 -- set interface veth4 ofport_request=2
sudo ovs-vsctl add-port switch1 veth6 -- set interface veth6 ofport_request=3 #interface do switch
sudo ovs-vsctl add-port switch1 veth7 -- set interface veth7 ofport_request=4 #interface switch1-switch2

sudo ovs-vsctl set bridge switch1 other-config:datapath-id=0000000000000001
sudo ovs-vsctl set-controller switch1 tcp:172.16.1.10:6653 
sudo ovs-vsctl set Bridge switch1 fail-mode=secure

echo "configurando as rotas"
sudo ip netns exec VRF1 ip route add 172.16.1.0/24 dev veth1
sudo ip netns exec VRF2 ip route add 172.16.1.0/24 dev veth3
sudo ip netns exec VRF1 ip route add 172.16.0.0/16 dev veth1
sudo ip netns exec VRF2 ip route add 172.16.0.0/16 dev veth3


sudo ip route add 172.16.1.0/24 dev veth5 #c#configurando interface do parent namespace para acessar o controlador-switchonfigurando interface do parent namespace para acessar o controlador-switch

# para rodar ping precisa configurar regras arp e icmp -- ja testei e funciona
# echo "tentando ping host (VRF1) to controller (VRF2)"
# sudo ip netns exec VRF1 ping -c 3 172.16.1.10 # funcionando
# echo "tentando ping controller (VRF2) to switch (Parent)"
# sudo ip netns exec VRF2 ping -c 3 172.16.1.50 # funcionando

echo "Removendo regra default (actions:=NORMAL) "
sudo ovs-ofctl del-flows switch1

echo "adicionando regra para switch alcançar controlador"
sudo ovs-ofctl add-flow switch1 arp,nw_dst=172.16.1.10,actions:outport=2 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch1 ip,nw_dst=172.16.1.10,actions:outport=2 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch1 icmp,nw_dst=172.16.1.10,actions:outport=2 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch1 arp,nw_dst=172.16.1.50,actions:outport=3
sudo ovs-ofctl add-flow switch1 icmp,nw_dst=172.16.1.50,actions:outport=3
sudo ovs-ofctl add-flow switch1 ip,nw_dst=172.16.1.50,actions:outport=3

# fazer o teste que tem que ser feito ( iperf ou seja la o que for )

echo "Dominio 1 configurado !"

#################################################################################################

echo "configurando domínio 2"
echo "Criando o namespace host dom 2"
sudo ip netns add VRF3

echo "Criando o namespace controller dom 2"
sudo ip netns add VRF4

echo "Listando namespaces"
sudo ip netns list

# qual fica para o host e qual fica para o switch ? o ímpar vai para o "host" e o par para o switch 
echo "Criando as portas veth9 e veth10 ( host -switch )"
sudo ip link add veth9 type veth peer name veth10

echo "Criando as portas veth11 e veth12 ( controller - switch )"
sudo ip link add veth11 type veth peer name veth12

echo "Criando as portas veth13 e veth14 ( eth0 (parent) - swith )"
sudo ip link add veth13 type veth peer name veth14

echo "Criando as portas veth15 e veth16 ( switch dom2 - switch dom3 )"
sudo ip link add veth15 type veth peer name veth16


echo "subindo as interfaces:"
sudo ifconfig veth9 up # host-switch
sudo ifconfig veth10 up # switch-host 6
sudo ifconfig veth11 up # controller-switch 
sudo ifconfig veth12 up # switch-controller 7
sudo ifconfig veth13 up # eth0-switch
sudo ifconfig veth14 up # switch-eth0 8
sudo ifconfig veth15 up # switch2-switch3 9
sudo ifconfig veth16 up # switch3-eth2

echo "configuring delay 5ms for each interface"
sudo tc qdisc add dev veth9 root netem delay 10ms
sudo tc qdisc add dev veth10 root netem delay 10ms
sudo tc qdisc add dev veth11 root netem delay 10ms
sudo tc qdisc add dev veth12 root netem delay 10ms
sudo tc qdisc add dev veth13 root netem delay 10ms
sudo tc qdisc add dev veth14 root netem delay 10ms
sudo tc qdisc add dev veth15 root netem delay 10ms
sudo tc qdisc add dev veth16 root netem delay 10ms

echo "Movendo as interfaces ímpares para dentro dos namespaces"
sudo ip link set veth9 netns VRF3
sudo ip link set veth11 netns VRF4

echo "Configurando IP e subindo as interfaces dentro do namespace"
sudo ip netns exec VRF3 ifconfig veth9 172.16.2.30/24
sudo ip netns exec VRF4 ifconfig veth11 172.16.2.10/24

echo "configurando interface de acesso ao switch2"
sudo ifconfig veth13 172.16.2.50/24

echo "Subindo os lo (loopback interfaces)"
sudo ip netns exec VRF3 ifconfig lo up
sudo ip netns exec VRF4 ifconfig lo up

echo "Configurando o switch do domínio 2"
sudo ovs-vsctl add-br switch2

sudo ovs-vsctl add-port switch2 veth8 -- set interface veth8 ofport_request=5 #interface do switch1-switch2
sudo ovs-vsctl add-port switch2 veth10 -- set interface veth10 ofport_request=6
sudo ovs-vsctl add-port switch2 veth12 -- set interface veth12 ofport_request=7
sudo ovs-vsctl add-port switch2 veth14 -- set interface veth14 ofport_request=8 #interface do switch
sudo ovs-vsctl add-port switch2 veth15 -- set interface veth15 ofport_request=9 #interface do switch

sudo ovs-vsctl set bridge switch2 other-config:datapath-id=0000000000000002
sudo ovs-vsctl set-controller switch2 tcp:172.16.2.10:6653 
sudo ovs-vsctl set Bridge switch2 fail-mode=secure

echo "configurando as rotas"
sudo ip netns exec VRF3 ip route add 172.16.2.0/24 dev veth9
sudo ip netns exec VRF4 ip route add 172.16.2.0/24 dev veth11
sudo ip netns exec VRF3 ip route add 172.16.0.0/16 dev veth9
sudo ip netns exec VRF4 ip route add 172.16.0.0/16 dev veth11

sudo ip route add 172.16.2.0/24 dev veth13 #c#configurando interface do parent namespace para acessar o controlador-switchonfigurando interface do parent namespace para acessar o controlador-switch

# para rodar ping precisa configurar regras arp e icmp -- ja testei e funciona
# echo "tentando ping host (VRF3) to controller (VRF4)"
# sudo ip netns exec VRF3 ping -c 3 172.16.2.10 # funcionando
# echo "tentando ping controller (VRF4) to switch (Parent)"
# sudo ip netns exec VRF4 ping -c 3 172.16.2.50 # funcionando

echo "Removendo regra default (actions:=NORMAL) "
sudo ovs-ofctl del-flows switch2

echo "adicionando regra para switch alcançar controlador"
sudo ovs-ofctl add-flow switch2 arp,nw_dst=172.16.2.10,actions:outport=7 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch2 ip,nw_dst=172.16.2.10,actions:outport=7 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch2 icmp,nw_dst=172.16.2.10,actions:outport=7 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch2 arp,nw_dst=172.16.2.50,actions:outport=8
sudo ovs-ofctl add-flow switch2 icmp,nw_dst=172.16.2.50,actions:outport=8
sudo ovs-ofctl add-flow switch2 ip,nw_dst=172.16.2.50,actions:outport=8

echo "Dominio 2 configurado !"

#################################################################################################

echo "configurando dominio 3"
echo "Criando o namespace host dom 3"
sudo ip netns add VRF5

echo "Criando o namespace controller dom 3"
sudo ip netns add VRF6


echo "Listando namespaces"
sudo ip netns list

# qual fica para o host e qual fica para o switch ? o ímpar vai para o "host" e o par para o switch 
echo "Criando as portas veth17 e veth18 ( host -switch )"
sudo ip link add veth17 type veth peer name veth18

echo "Criando as portas veth19 e veth20 ( controller - switch )"
sudo ip link add veth19 type veth peer name veth20

echo "Criando as portas veth21 e veth22 ( eth0 (parent) - swith )"
sudo ip link add veth21 type veth peer name veth22

echo "Criando as portas veth23 e veth24 ( switch dom3 - switch dom4 )"
sudo ip link add veth23 type veth peer name veth24

echo "Subindo interfaces"
#               veth16 switch2-switch3 10
sudo ifconfig veth17 up # host-switch
sudo ifconfig veth18 up # switch-host 11 
sudo ifconfig veth19 up # controller-switch
sudo ifconfig veth20 up # switch-controller 12
sudo ifconfig veth21 up # eth0-switch
sudo ifconfig veth22 up # switch-eth0 13
sudo ifconfig veth23 up # switch3-switch4 14
sudo ifconfig veth24 up # switch4-switch3

echo "configuring delay 5ms for each interface"
sudo tc qdisc add dev veth17 root netem delay 10ms
sudo tc qdisc add dev veth18 root netem delay 10ms
sudo tc qdisc add dev veth19 root netem delay 10ms
sudo tc qdisc add dev veth20 root netem delay 10ms
sudo tc qdisc add dev veth21 root netem delay 10ms
sudo tc qdisc add dev veth22 root netem delay 10ms
sudo tc qdisc add dev veth23 root netem delay 10ms
sudo tc qdisc add dev veth24 root netem delay 10ms

echo "Movendo as interfaces ímpares para dentro dos namespaces"
sudo ip link set veth17 netns VRF5
sudo ip link set veth19 netns VRF6

echo "Configurando IP e subindo as interfaces dentro do namespace"
sudo ip netns exec VRF5 ifconfig veth17 172.16.3.30/24
sudo ip netns exec VRF6 ifconfig veth19 172.16.3.10/24

echo "configurando interface de acesso ao switch1"
sudo ifconfig veth21 172.16.3.50/24

echo "Subindo os lo (loopback interfaces)"
sudo ip netns exec VRF5 ifconfig lo up
sudo ip netns exec VRF6 ifconfig lo up

echo "Configurando o switch do domínio 3"
sudo ovs-vsctl add-br switch3

sudo ovs-vsctl add-port switch3 veth16 -- set interface veth16 ofport_request=10
sudo ovs-vsctl add-port switch3 veth18 -- set interface veth18 ofport_request=11
sudo ovs-vsctl add-port switch3 veth20 -- set interface veth20 ofport_request=12 #interface do switch
sudo ovs-vsctl add-port switch3 veth22 -- set interface veth22 ofport_request=13 #switch - eth0
sudo ovs-vsctl add-port switch3 veth23 -- set interface veth23 ofport_request=14 #interface switch1-switch2

sudo ovs-vsctl set bridge switch3 other-config:datapath-id=0000000000000003
sudo ovs-vsctl set-controller switch3 tcp:172.16.3.10:6653 
sudo ovs-vsctl set Bridge switch3 fail-mode=secure

echo "configurando as rotas"
sudo ip netns exec VRF5 ip route add 172.16.3.0/24 dev veth17
sudo ip netns exec VRF6 ip route add 172.16.3.0/24 dev veth19
sudo ip netns exec VRF5 ip route add 172.16.0.0/16 dev veth17
sudo ip netns exec VRF6 ip route add 172.16.0.0/16 dev veth19

sudo ip route add 172.16.3.0/24 dev veth21 #c#configurando interface do parent namespace para acessar o controlador-switchonfigurando interface do parent namespace para acessar o controlador-switch

# para rodar ping precisa configurar regras arp e icmp -- ja testei e funciona
# echo "tentando ping host (VRF5) to controller (VRF6)"
# sudo ip netns exec VRF5 ping -c 3 172.16.3.10 # funcionando
# echo "tentando ping controller (VRF6) to switch (Parent)"
# sudo ip netns exec VRF6 ping -c 3 172.16.3.50 # funcionando

echo "Removendo regra default (actions:=NORMAL) "
sudo ovs-ofctl del-flows switch3

echo "adicionando regra para switch alcançar controlador"
sudo ovs-ofctl add-flow switch3 arp,nw_dst=172.16.3.10,actions:outport=12 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch3 ip,nw_dst=172.16.3.10,actions:outport=12 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch3 icmp,nw_dst=172.16.3.10,actions:outport=12 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch3 arp,nw_dst=172.16.3.50,actions:outport=13
sudo ovs-ofctl add-flow switch3 icmp,nw_dst=172.16.3.50,actions:outport=13
sudo ovs-ofctl add-flow switch3 ip,nw_dst=172.16.3.50,actions:outport=13
# fazer o teste que tem que ser feito ( iperf ou seja la o que for )

echo "Dominio 3 configurado !"

#################################################################################################


echo "configurando dominio 4"
echo "Criando o namespace host dom 4"
sudo ip netns add VRF7

echo "Criando o namespace controller dom 4"
sudo ip netns add VRF8


echo "Listando namespaces"
sudo ip netns list

# qual fica para o host e qual fica para o switch ? o ímpar vai para o "host" e o par para o switch 
echo "Criando as portas veth25 e veth26 ( host -switch )"
sudo ip link add veth25 type veth peer name veth26

echo "Criando as portas veth27 e veth28 ( controller - switch )"
sudo ip link add veth27 type veth peer name veth28

echo "Criando as portas veth29 e veth30 ( eth0 (parent) - swith )"
sudo ip link add veth29 type veth peer name veth30

echo "Criando as portas veth31 e veth32 ( switch dom4 - switch dom5 )"
sudo ip link add veth31 type veth peer name veth32

echo "Subindo interfaces"
#              veth24   switch3-switch4 15
sudo ifconfig veth25 up # host-switch
sudo ifconfig veth26 up # switch-host 16
sudo ifconfig veth27 up # controller-switch
sudo ifconfig veth28 up # switch-controller 17
sudo ifconfig veth29 up # eth0-switch
sudo ifconfig veth30 up # switch-eth0 18
sudo ifconfig veth31 up # switch4-switch5 19
sudo ifconfig veth32 up # switch5-switch4

echo "configuring delay 5ms for each interface"
sudo tc qdisc add dev veth25 root netem delay 10ms
sudo tc qdisc add dev veth26 root netem delay 10ms
sudo tc qdisc add dev veth27 root netem delay 10ms
sudo tc qdisc add dev veth28 root netem delay 10ms
sudo tc qdisc add dev veth29 root netem delay 10ms
sudo tc qdisc add dev veth30 root netem delay 10ms
sudo tc qdisc add dev veth31 root netem delay 10ms
sudo tc qdisc add dev veth32 root netem delay 10ms

echo "Movendo as interfaces ímpares para dentro dos namespaces"
sudo ip link set veth25 netns VRF7
sudo ip link set veth27 netns VRF8

echo "Configurando IP e subindo as interfaces dentro do namespace"
sudo ip netns exec VRF7 ifconfig veth25 172.16.4.30/24
sudo ip netns exec VRF8 ifconfig veth27 172.16.4.10/24

echo "configurando interface de acesso ao switch1"
sudo ifconfig veth29 172.16.4.50/24

echo "Subindo os lo (loopback interfaces)"
sudo ip netns exec VRF7 ifconfig lo up
sudo ip netns exec VRF8 ifconfig lo up

echo "Configurando o switch do domínio 4"
sudo ovs-vsctl add-br switch4

sudo ovs-vsctl add-port switch4 veth24 -- set interface veth24 ofport_request=15
sudo ovs-vsctl add-port switch4 veth26 -- set interface veth26 ofport_request=16
sudo ovs-vsctl add-port switch4 veth28 -- set interface veth28 ofport_request=17 #interface do switch
sudo ovs-vsctl add-port switch4 veth30 -- set interface veth30 ofport_request=18 #interface switch1-switch2
sudo ovs-vsctl add-port switch4 veth31 -- set interface veth31 ofport_request=19 #interface switch1-switch2

sudo ovs-vsctl set bridge switch4 other-config:datapath-id=0000000000000004
sudo ovs-vsctl set-controller switch4 tcp:172.16.4.10:6653 
sudo ovs-vsctl set Bridge switch4 fail-mode=secure

echo "configurando as rotas"
sudo ip netns exec VRF7 ip route add 172.16.4.0/24 dev veth25
sudo ip netns exec VRF8 ip route add 172.16.4.0/24 dev veth27
sudo ip netns exec VRF7 ip route add 172.16.0.0/16 dev veth25
sudo ip netns exec VRF8 ip route add 172.16.0.0/16 dev veth27

sudo ip route add 172.16.4.0/24 dev veth29 #c#configurando interface do parent namespace para acessar o controlador-switchonfigurando interface do parent namespace para acessar o controlador-switch

# para rodar ping precisa configurar regras arp e icmp -- ja testei e funciona
# echo "tentando ping host (VRF7) to controller (VRF8)"
# sudo ip netns exec VRF7 ping -c 3 172.16.4.10 # funcionando
# echo "tentando ping controller (VRF8) to switch (Parent)"
# sudo ip netns exec VRF8 ping -c 3 172.16.4.50 # funcionando

echo "Removendo regra default (actions:=NORMAL) "
sudo ovs-ofctl del-flows switch4

echo "adicionando regra para switch alcançar controlador"
sudo ovs-ofctl add-flow switch4 arp,nw_dst=172.16.4.10,actions:outport=17 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch4 ip,nw_dst=172.16.4.10,actions:outport=17 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch4 icmp,nw_dst=172.16.4.10,actions:outport=17 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch4 arp,nw_dst=172.16.4.50,actions:outport=18
sudo ovs-ofctl add-flow switch4 icmp,nw_dst=172.16.4.50,actions:outport=18
sudo ovs-ofctl add-flow switch4 ip,nw_dst=172.16.4.50,actions:outport=18

# fazer o teste que tem que ser feito ( iperf ou seja la o que for )

echo "Dominio 4 configurado !"

#################################################################################################

echo "configurando dominio 5"
echo "Criando o namespace host dom 5"
sudo ip netns add VRF9

echo "Criando o namespace controller dom 5"
sudo ip netns add VRF10

echo "Listando namespaces"
sudo ip netns list

# qual fica para o host e qual fica para o switch ? o ímpar vai para o "host" e o par para o switch 
echo "Criando as portas veth33 e veth34 ( host dom5 )"
sudo ip link add veth33 type veth peer name veth34

echo "Criando as portas veth35 e veth36 ( controller dom5 )"
sudo ip link add veth35 type veth peer name veth36

echo "Criando as portas veth37 e veth38 ( eth0(parent) - switch )"
sudo ip link add veth37 type veth peer name veth38

# echo "Criando as portas veth7 e veth8 ( switch dom5 - switch dom6 )" # nao temos proximo dominio
# sudo ip link add veth7 type veth peer name veth8

echo "Subindo interfaces"
#             veth32 up  switch5-switch4 20
sudo ifconfig veth33 up # host-switch
sudo ifconfig veth34 up # switch-host 21
sudo ifconfig veth35 up # controller-switch 
sudo ifconfig veth36 up # switch-controller 22
sudo ifconfig veth37 up # eth0-switch
sudo ifconfig veth38 up # switch-eth0 23

echo "configuring delay 5ms for each interface"
sudo tc qdisc add dev veth33 root netem delay 10ms
sudo tc qdisc add dev veth34 root netem delay 10ms
sudo tc qdisc add dev veth35 root netem delay 10ms
sudo tc qdisc add dev veth36 root netem delay 10ms
sudo tc qdisc add dev veth37 root netem delay 10ms
sudo tc qdisc add dev veth38 root netem delay 10ms

echo "Movendo as interfaces ímpares para dentro dos namespaces"
sudo ip link set veth33 netns VRF9
sudo ip link set veth35 netns VRF10

echo "Configurando IP e subindo as interfaces dentro do namespace"
sudo ip netns exec VRF9 ifconfig veth33 172.16.5.30/24
sudo ip netns exec VRF10 ifconfig veth35 172.16.5.10/24

echo "configurando interface de acesso ao switch5"
sudo ifconfig veth37 172.16.5.50/24

echo "Subindo os lo (loopback interfaces)"
sudo ip netns exec VRF9 ifconfig lo up
sudo ip netns exec VRF10 ifconfig lo up

echo "Configurando o switch do domínio 5"
sudo ovs-vsctl add-br switch5

sudo ovs-vsctl add-port switch5 veth32 -- set interface veth32 ofport_request=20
sudo ovs-vsctl add-port switch5 veth34 -- set interface veth34 ofport_request=21
sudo ovs-vsctl add-port switch5 veth36 -- set interface veth36 ofport_request=22 #interface do switch
sudo ovs-vsctl add-port switch5 veth38 -- set interface veth38 ofport_request=23 #interface switch1-switch2

sudo ovs-vsctl set bridge switch5 other-config:datapath-id=0000000000000005
sudo ovs-vsctl set-controller switch5 tcp:172.16.5.10:6653 
sudo ovs-vsctl set Bridge switch5 fail-mode=secure

echo "configurando as rotas"
sudo ip netns exec VRF9 ip route add 172.16.5.0/24 dev veth33
sudo ip netns exec VRF10 ip route add 172.16.5.0/24 dev veth35
sudo ip netns exec VRF9 ip route add 172.16.0.0/16 dev veth33
sudo ip netns exec VRF10 ip route add 172.16.0.0/16 dev veth35

sudo ip route add 172.16.5.0/24 dev veth37 #c#configurando interface do parent namespace para acessar o controlador-switchonfigurando interface do parent namespace para acessar o controlador-switch

# para rodar ping precisa configurar regras arp e icmp -- ja testei e funciona
# echo "tentando ping host (VRF9) to controller (VRF10)"
# sudo ip netns exec VRF9 ping -c 3 172.16.5.10 # funcionando
# echo "tentando ping controller (VRF10) to switch (Parent)"
# sudo ip netns exec VRF10 ping -c 3 172.16.5.50 # funcionando

echo "Removendo regra default (actions:=NORMAL) "
sudo ovs-ofctl del-flows switch5

echo "adicionando regra para switch alcançar controlador"
sudo ovs-ofctl add-flow switch5 arp,nw_dst=172.16.5.10,actions:outport=22 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch5 ip,nw_dst=172.16.5.10,actions:outport=22 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch5 icmp,nw_dst=172.16.5.10,actions:outport=22 # alcancar controlador(flowpri)
sudo ovs-ofctl add-flow switch5 arp,nw_dst=172.16.5.50,actions:outport=23
sudo ovs-ofctl add-flow switch5 icmp,nw_dst=172.16.5.50,actions:outport=23
sudo ovs-ofctl add-flow switch5 ip,nw_dst=172.16.5.50,actions:outport=23


# fazer o teste que tem que ser feito ( iperf ou seja la o que for )

echo "Dominio 5 configurado !"

#################################################################################################


####################################################################################3
echo "Gerando as pastas para cada host e subindo os terminais de acesso !"


cp -r ../../FLOWPRI-SDN2 ../../controlador1 # criar uma pasta para cada controlador 
cp cfgDom1.json ../../controlador1/cfg.json

cp -r ../../FLOWPRI-SDN2 ../../controlador2 # criar uma pasta para cada controlador 
cp cfgDom2.json ../../controlador2/cfg.json

cp -r ../../FLOWPRI-SDN2 ../../controlador3 # criar uma pasta para cada controlador 
cp cfgDom3.json ../../controlador3/cfg.json

cp -r ../../FLOWPRI-SDN2 ../../controlador4 # criar uma pasta para cada controlador 
cp cfgDom4.json ../../controlador4/cfg.json

cp -r ../../FLOWPRI-SDN2 ../../controlador5 # criar uma pasta para cada controlador 
cp cfgDom5.json ../../controlador5/cfg.json

###

cp -r ../../FLOWPRI-SDN2 ../../host1/ # criar uma pasta para cada host
cp -r ../../FLOWPRI-SDN2 ../../host2/ # criar uma pasta para cada host
cp -r ../../FLOWPRI-SDN2 ../../host3/ # criar uma pasta para cada host
cp -r ../../FLOWPRI-SDN2 ../../host4/ # criar uma pasta para cada host
cp -r ../../FLOWPRI-SDN2 ../../host5/ # criar uma pasta para cada host

###

# sudo ip netns exec VRF1 xterm -e sh run_management_host.sh &
sudo ip netns exec VRF1 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host1-main-term -hold -e "cd ../../host1 && /bin/bash" & # subir os hosts
sudo ip netns exec VRF1 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host1-qos-manag -hold -l -lf ../../h1_conventional.log -e "cd ../../host1 && sh run_conventional_host.sh && /bin/bash" & # ver se roda em background
sudo ip netns exec VRF1 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host1-fredEbkchain-serv -hold -l -lf ../../h1_management.log -e "cd ../../host1 && sh run_management_host.sh && /bin/bash" &

sudo ip netns exec VRF3 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host2-main-term -hold -e "cd ../../host2 && /bin/bash" & # subir os hosts
sudo ip netns exec VRF3 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host2-qos-manag -hold -l -lf ../../h2_convencional.log -e "cd ../../host2 && sh run_conventional_host.sh && /bin/bash" & # ver se roda em background
sudo ip netns exec VRF3 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host2-fredEbkchain-serv -hold -l -lf ../../h2_management.log -e "cd ../../host2 && sh run_management_host.sh && /bin/bash" &

sudo ip netns exec VRF5 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host3-main-term -hold -e "cd ../../host3 && /bin/bash" & # subir os hosts
sudo ip netns exec VRF5 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host3-qos-manag -hold -l -lf ../../h3_convencional.log -e "cd ../../host3 && sh run_conventional_host.sh && /bin/bash" & # ver se roda em background
sudo ip netns exec VRF5 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host3-fredEbkchain-serv -hold -l -lf ../../h3_management.log -e "cd ../../host3 && sh run_management_host.sh && /bin/bash" &

sudo ip netns exec VRF7 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host4-main-term -hold -e "cd ../../host4 && /bin/bash" & # subir os hosts
sudo ip netns exec VRF7 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host4-qos-manag -hold -l -lf ../../h4_convencional.log -e "cd ../../host4 && sh run_conventional_host.sh && /bin/bash" & # ver se roda em background
sudo ip netns exec VRF7 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host4-fredEbkchain-serv -hold -l -lf ../../h4_management.log -e "cd ../../host4 && sh run_management_host.sh && /bin/bash" &

sudo ip netns exec VRF9 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host5-main-term -hold -e "cd ../../host5 && /bin/bash" & # subir os hosts
sudo ip netns exec VRF9 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host5-qos-manag -hold -l -lf ../../h5_convencional.log -e "cd ../../host5 && sh run_conventional_host.sh && /bin/bash" & # ver se roda em background
sudo ip netns exec VRF9 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T host5-fredEbkchain-serv -hold -l -lf ../../h5_management.log -e "cd ../../host5 && sh run_management_host.sh && /bin/bash" &


# sudo ip netns exec VRF2 xterm -e sh run_flowpri2.sh &
sudo ip netns exec VRF2 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T controller1-flowpri2 -hold -l -lf ../../c1.log -e "cd ../../controlador1 && sh run_flowpri2.sh && /bin/bash" & #&& sh run_flowpri2.sh && /bin/bash" & # subir os hosts servers
sudo ip netns exec VRF4 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T controller2-flowpri2 -hold -l -lf ../../c2.log -e "cd ../../controlador2  && sh run_flowpri2.sh  && /bin/bash" & #&& sh run_flowpri2.sh && /bin/bash" & # subir os hosts servers
sudo ip netns exec VRF6 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T controller3-flowpri2 -hold -l -lf ../../c3.log -e "cd ../../controlador3  && sh run_flowpri2.sh && /bin/bash" & #&& sh run_flowpri2.sh && /bin/bash" & # subir os hosts servers
sudo ip netns exec VRF8 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T controller4-flowpri2 -hold -l -lf ../../c4.log -e "cd ../../controlador4  && sh run_flowpri2.sh && /bin/bash" & #&& sh run_flowpri2.sh && /bin/bash" & # subir os hosts servers
sudo ip netns exec VRF10 xterm -xrm 'XTerm.vt100.allowTitleOps: false' -T controller5-flowpri2 -hold -l -lf ../../c5.log -e "cd ../../controlador5 && sh run_flowpri2.sh && /bin/bash" & # && sh run_flowpri2.sh && /bin/bash" & # subir os hosts servers


# criar o qosblockchainv1
echo "Montando imagens docker"
sudo docker image pull hyperledger/sawtooth-rest-api:chime
sudo docker image pull hyperledger/sawtooth-settings-tp:chime
sudo docker image pull hyperledger/sawtooth-validator:chime
sudo docker image pull hyperledger/sawtooth-pbft-engine:chime
cd ../qosblockchain/one_container; sudo docker build --debug --tag 'qosblockchainv1' .; 
cd ../../../;

echo "Pronto para iniciar!"

echo "Encerre o experimento executando end_experiment.sh !"
