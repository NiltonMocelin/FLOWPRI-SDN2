echo "Running Setup scritp"

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

echo "Movendo as interfaces ímpares para dentro dos namespaces"
sudo ip link set veth1 netns VRF1
sudo ip link set veth3 netns VRF2

echo "Configurando IP e subindo as interfaces dentro do namespace"
sudo ip netns exec VRF1 ifconfig veth1 172.16.1.30/24 up
sudo ip netns exec VRF2 ifconfig veth3 172.16.1.10/24 up


echo "Configurando o switch do domínio 1"
sudo ovs-vsctl add-br switch1

sudo ovs-vsctl add-port switch1 veth2
sudo ovs-vsctl add-port switch1 veth4

sudo ifconfig veth2 up
sudo ifconfig veth4 up

echo "tentando ping host (VRF1) to controller (VRF2)"
sudo ip netns exec VRF1 ping -c 5 172.1.1.10

echo "Removendo regra default (actions:=NORMAL) "
sudo ovs-ofctl del-flows switch1

echo "Tudo pronto para começar !"

# subir o controlador

# subir os hosts servers

# fazer o teste que tem que ser feito ( iperf ou seja la o que for )



echo "Encerre o experimento executando end_experiment.sh !"