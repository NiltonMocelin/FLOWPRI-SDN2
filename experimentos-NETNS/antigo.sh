
echo "Running Setup scritp - PRESUPOSTO QUE O REQUIREMENTS.SH FOI EXECUTADO"


#################################################################################################
echo "Ambiente com 1 domínio" # testando, se rodar tudo certinho, fazer para dois e .. 5

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

# echo "Criando as portas veth7 e veth8 ( switch dom1 - switch dom2 )"
# sudo ip link add veth7 type veth peer name veth8


echo "Movendo as interfaces ímpares para dentro dos namespaces"
sudo ip link set veth1 netns VRF1
sudo ip link set veth3 netns VRF2

echo "Configurando IP e subindo as interfaces dentro do namespace"
sudo ip netns exec VRF1 ifconfig veth1 172.16.1.30/24 up
sudo ip netns exec VRF2 ifconfig veth3 172.16.1.10/24 up

# interface do switch
sudo ifconfig veth5 172.16.1.50/24 up

echo "Subindo os lo (loopback interfaces)"
sudo ip netns exec VRF1 ifconfig lo up
sudo ip netns exec VRF2 ifconfig lo up

echo "Configurando o switch do domínio 1"
sudo ovs-vsctl add-br switch1

sudo ovs-vsctl add-port switch1 veth2 -- set interface veth1 ofport_request=1
sudo ovs-vsctl add-port switch1 veth4 -- set interface veth2 ofport_request=2
#interface do switch
sudo ovs-vsctl add-port switch1 veth6 -- set interface veth6 ofport_request=3


#### isso aqui eh duvidoso pode estar dando erro o resto esta correto (todos os outros comandos testados e funcionando)
sudo ovs-vsctl set bridge switch1 other-config:datapath-id=0000000000000001
sudo ovs-vsctl set-controller switch1 tcp:172.16.1.10:6653 
sudo ovs-vsctl set Bridge switch fail-mode=secure
####

sudo ifconfig veth2 up
sudo ifconfig veth4 up

echo "configurando as rotas"
sudo ip netns exec VRF1 ip route add 172.16.1.0/24 dev veth1
sudo ip netns exec VRF2 ip route add 172.16.1.0/24 dev veth3
#configurando interface do parent namespace para acessar o controlador-switch
sudo ip route add 172.16.1.0/24 dev veth5

echo "tentando ping host (VRF1) to controller (VRF2)"
sudo ip netns exec VRF1 ping -c 3 172.16.1.10 # funcionando


echo "tentando ping controller (VRF2) to switch (Parent)"
sudo ip netns exec VRF2 ping -c 3 172.16.1.50 # funcionando

echo "Removendo regra default (actions:=NORMAL) "
sudo ovs-ofctl del-flows switch1

echo "Tudo pronto para começar !"

# criar uma pasta para cada controlador 
cp -r ../../FLOWPRI-SDN2 ../../controlador1
cp experimentos-NETNS/cfgDom1.json ../../controlador1/cfg.json

# criar uma pasta para cada host
cp -r ../../FLOWPRI-SDN2 ../../host1/

# subir o controlador
cd ../../host1/FLOWPRI-SDN2
# sudo ip netns exec VRF1 xterm -e sh run_management_host.sh &
sudo ip netns exec VRF1 xterm &


# subir os hosts servers
cd ../../controlador1
# sudo ip netns exec VRF2 xterm -e sh run_flowpri2.sh &
sudo ip netns exec VRF2 xterm &


### voltando para pasta anterior
cd ../../FLOWPRI-SDN2

# fazer o teste que tem que ser feito ( iperf ou seja la o que for )

echo "Dominio 1 configurado !"

#################################################################################################









echo "Encerre o experimento executando end_experiment.sh !"

# 11:22 bateria 100%
# 12:18 bateria 80%   
# 13:36 bateria 43%