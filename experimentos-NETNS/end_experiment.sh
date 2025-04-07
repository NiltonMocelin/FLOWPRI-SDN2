
# fechar o controlador

# fechar os hosts servers

echo "Removendo configuracoes de filas"
sudo ovs-vsctl --all destroy qos

echo "Removendo switch1"
sudo ovs-vsctl del-port switch1 veth4
sudo ovs-vsctl del-port switch1 veth2
sudo ovs-vsctl del-br switch1

echo "Removendo vInterfaces das namespaces"
sudo ip netns exec VRF1 ip link del veth1
sudo ip netns exec VRF2 ip link del veth3 # remove o par

echo "Removendo namespaces"
sudo ip netns del VRF1
sudo ip netns del VRF2

echo "Tudo pronto !"
sudo ip link

