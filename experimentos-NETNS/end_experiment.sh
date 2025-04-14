
# fechar o controlador
# tem que ver como fazer isso

# fechar os hosts servers
# tem que ver como fazer isso

echo "Removendo switches"
sudo ovs-vsctl del-port switch1 veth2
sudo ovs-vsctl del-port switch1 veth4
sudo ovs-vsctl del-port switch1 veth6 
sudo ovs-vsctl del-port switch1 veth7
sudo ovs-vsctl del-port switch2 veth8
sudo ovs-vsctl del-port switch2 veth10
sudo ovs-vsctl del-port switch2 veth12
sudo ovs-vsctl del-port switch2 veth14
sudo ovs-vsctl del-port switch2 veth15
sudo ovs-vsctl del-port switch3 veth16
sudo ovs-vsctl del-port switch3 veth18
sudo ovs-vsctl del-port switch3 veth20
sudo ovs-vsctl del-port switch3 veth22
sudo ovs-vsctl del-port switch3 veth23
sudo ovs-vsctl del-port switch4 veth24
sudo ovs-vsctl del-port switch4 veth26
sudo ovs-vsctl del-port switch4 veth28
sudo ovs-vsctl del-port switch4 veth30
sudo ovs-vsctl del-port switch4 veth31
sudo ovs-vsctl del-port switch5 veth32
sudo ovs-vsctl del-port switch5 veth34
sudo ovs-vsctl del-port switch5 veth36
sudo ovs-vsctl del-port switch5 veth38
sudo ovs-vsctl del-br switch1
sudo ovs-vsctl del-br switch2
sudo ovs-vsctl del-br switch3
sudo ovs-vsctl del-br switch4
sudo ovs-vsctl del-br switch5

echo "Removendo configuracoes de filas"
sudo ovs-vsctl --all destroy qos

# echo "Removendo vInterfaces das namespaces"
# sudo ip netns exec VRF1 ip link del veth1
# sudo ip netns exec VRF2 ip link del veth3 # remove o par

# remover rota para controlador-switch
echo "removendo rotas"
sudo ip route del 172.16.1.0/24 dev veth5
sudo ip route del 172.16.2.0/24 dev veth13
sudo ip route del 172.16.3.0/24 dev veth21 
sudo ip route del 172.16.4.0/24 dev veth29
sudo ip route del 172.16.5.0/24 dev veth37


#remover interfaces - remove os pares
echo "Removendo interfaces"
sudo ip link del veth2
sudo ip link del veth4
sudo ip link del veth6 
sudo ip link del veth8
sudo ip link del veth10
sudo ip link del veth12
sudo ip link del veth14
sudo ip link del veth16
sudo ip link del veth18
sudo ip link del veth20
sudo ip link del veth22
sudo ip link del veth24
sudo ip link del veth26
sudo ip link del veth28
sudo ip link del veth30
sudo ip link del veth32
sudo ip link del veth34
sudo ip link del veth36
sudo ip link del veth38


echo "Removendo namespaces"
sudo ip netns del VRF1
sudo ip netns del VRF2
sudo ip netns del VRF3
sudo ip netns del VRF4
sudo ip netns del VRF5
sudo ip netns del VRF6
sudo ip netns del VRF7
sudo ip netns del VRF8
sudo ip netns del VRF9
sudo ip netns del VRF10

echo "Matando terminais xterm"
sudo killall xterm

echo "Removendo pastas dos hosts e controladores"
sudo rm -r ../../controlador1
sudo rm -r ../../host1
sudo rm -r ../../controlador2
sudo rm -r ../../host2
sudo rm -r ../../controlador3
sudo rm -r ../../host3
sudo rm -r ../../controlador4
sudo rm -r ../../host4
sudo rm -r ../../controlador5
sudo rm -r ../../host5

echo "Removendo todos os containeres e imagens (todos os com nome 172) se der erro eh pq nao tem ativos"
sudo docker stop $(sudo docker ps -a | grep 172 | awk '{print $1}')
sudo docker stop $(sudo docker ps -a | grep sawtooth | awk '{print $1}')
sudo docker rm $(sudo docker ps -a | grep 172 | awk '{print $1}')
sudo docker rm $(sudo docker ps -a | grep sawtooth | awk '{print $1}')

sudo docker image rm $(sudo docker image ls | grep sawtooth | awk '{print $3}')

echo "Tudo limpo -> Experimento encerrado !"
sudo ip link
sudo ip netns list
