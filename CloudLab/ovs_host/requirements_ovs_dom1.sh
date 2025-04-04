# criar interface ovs
# criar bridge da interface criada com as interfaces existentes
# existem dois comportamentos básicos que precsa se atentar (LOCAL e NORMAL)
# precisa ter instalado python3.8 e ovs ==> rodar o requirements_controller_host_switch.sh

# configurando o switch

sudo ovs-vsctl add-br switch \
         -- set bridge switch other-config:datapath-id=0000000000000001 \
         -- add-port switch eth1 -- set interface eth1 ofport_request=1 \
         -- add-port switch eth2 -- set interface eth2 ofport_request=2 \
         -- add-port switch eth3 -- set interface eth3 ofport_request=3 \
         -- set-controller switch tcp:172.16.1.10:6653 \
         -- set controller switch connection-mode=out-of-band
# explicando o comando sudo ovs-vsctl anterior: switch é o nome da bridge ovs que vamos utilizar.
# set datapath-id é o nome do switch para o controlador
# add-port: adicionar interfaces a bridge switch, para que este possa controlar as interfaces como se fossem portas de um switch
# ofport_request é o nome da porta para o switch, que é utilizada nas acões das regras openflow 
# set controller, define o controlador que gerencia o switch
# switch connection=mode=out-of-band , define que as mensagens openflow devem passar pelos switches e não diretamente
