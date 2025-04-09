# configurando o switch
echo "Iniciando configuracao OVS"

echo "Descobrindo qual interface conecta a cada host"

# interface que conecta com H1
INTH1=$(ip -br addr show to 172.16.1.40 | awk '{print $1}')
# interface que conecta com C1
INTC1=$(ip -br addr show to 172.16.1.20 | awk '{print $1}')
# interface que conecta com Switches numeros maiores
INTSMA=$(ip -br addr show to 172.16.1.60 | awk '{print $1}')
# interface que conecta com Switches numeros menores
INTSME=$(ip -br addr show to 172.16.1.50 | awk '{print $1}')

echo "Retirar o ip de cada interface, pois se não, o ovs não é capaz de gerencia-los"
sudo ifconfig $INTH1 0
sudo ifconfig $INTC1 0
sudo ifconfig $INTSMA 0
sudo ifconfig $INTSME 0

sudo ovs-vsctl add-br switch
sudo ovs-vsctl set bridge switch other-config:datapath-id=0000000000000001
sudo ovs-vsctl set-controller switch tcp:172.16.1.10:6653 
sudo ovs-vsctl set Bridge switch fail-mode=secure

sudo ovs-vsctl add-port switch eth1 
sudo ovs-vsctl add-port switch eth2 
sudo ovs-vsctl add-port switch eth3 
sudo ovs-vsctl set interface eth1 ofport_request=1
sudo ovs-vsctl set interface eth2 ofport_request=2
sudo ovs-vsctl set interface eth3 ofport_request=3

echo "Setando ip para a bridge/switch"
sudo ifconfig switch up
sudo ifconfig switch 172.16.1.40/24
