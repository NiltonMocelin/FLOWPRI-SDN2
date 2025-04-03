# criar interface ovs
# criar bridge da interface criada com as interfaces existentes
# existem dois comportamentos básicos que precsa se atentar (LOCAL e NORMAL)
sudo apt update
sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev

# install python3.8
wget https://www.python.org/ftp/python/3.8.0/Python-3.8.0.tgz
tar -xf Python-3.8.0.tgz
cd Python-3.8.0
./configure --enable-optimizations
make -j 8
sudo make altinstall

sudo apt-get install openvswitch-switch openvswitch-switch-dpdk openvswitch-common

# configurando o switch

sudo ovs-vsctl add-br switch \
         -- set bridge switch other-config:datapath-id=0000000000000003 \
         -- add-port switch eth1 -- set interface eth1 ofport_request=1 \
         -- add-port switch eth2 -- set interface eth2 ofport_request=2 \
         -- add-port switch eth3 -- set interface eth3 ofport_request=3 \
         -- add-port switch eth4 -- set interface eth4 ofport_request=4 \
         -- set-controller switch tcp:172.16.2.10:6653 \
         -- set controller switch connection-mode=out-of-band
# explicando o comando sudo ovs-vsctl anterior: switch é o nome da bridge ovs que vamos utilizar.
# set datapath-id é o nome do switch para o controlador
# add-port: adicionar interfaces a bridge switch, para que este possa controlar as interfaces como se fossem portas de um switch
# ofport_request é o nome da porta para o switch, que é utilizada nas acões das regras openflow 
# set controller, define o controlador que gerencia o switch
# switch connection=mode=out-of-band , define que as mensagens openflow devem passar pelos switches e não diretamente
