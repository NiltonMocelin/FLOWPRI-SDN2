# configurando o switch
echo "Iniciando configuracao OVS"

echo "Descobrindo qual interface conecta a cada host"

# interface que conecta com H1
INTH1=$(ip -br addr show to 172.16.2.40 | awk '{print $1}')
# interface que conecta com C1
INTC1=$(ip -br addr show to 172.16.2.20 | awk '{print $1}')
# interface que conecta com Switches numeros maiores
INTSMA=$(ip -br addr show to 172.16.2.60 | awk '{print $1}')
# interface que conecta com Switches numeros menores
INTSME=$(ip -br addr show to 172.16.2.50 | awk '{print $1}')

echo "Retirar o ip de cada interface, pois se não, o ovs não é capaz de gerencia-los"
sudo ifconfig $INTH1 0
sudo ifconfig $INTC1 0
sudo ifconfig $INTSMA 0
sudo ifconfig $INTSME 0

sudo ovs-vsctl add-br switch
sudo ifconfig switch up
# sudo ovs-vsctl set bridge switch other-config:datapath-id=0000000000000002
# sudo ovs-vsctl set-controller switch tcp:172.16.2.10:6653  # comando dando pau

sudo ovs-vsctl add-port switch eth1 
sudo ovs-vsctl add-port switch eth2 
sudo ovs-vsctl add-port switch eth3 
sudo ovs-vsctl add-port switch eth4 
sudo ovs-vsctl set interface eth1 ofport_request=1
sudo ovs-vsctl set interface eth2 ofport_request=2
sudo ovs-vsctl set interface eth3 ofport_request=3
sudo ovs-vsctl set interface eth3 ofport_request=4

echo "Setando ip para a bridge/switch"
sudo ifconfig switch 172.16.2.40/24
