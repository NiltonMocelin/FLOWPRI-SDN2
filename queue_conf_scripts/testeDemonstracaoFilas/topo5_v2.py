#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.node import CPULimitedHost, OVSKernelSwitch
from mininet.util import dumpNodeConnections

#Topologia: Os roots sao hosts fora do espaco de rede do mininet, mas que estao conectados com o switch por meio de um link e com o controlador, por meio de um socket. Esta foi a melhor maneira que encontrei para fazer a conexao entre hosts e controlador, assim, tudo que for encaminhado para root1 sera repassado para o socket em c0 (contrato).
#Pq fazer assim: (1)se subisse o controlador no root1, o controlador por algum motivo nao se conecta com o switch s1. (2)aparentemente nao se pode criar interfaces no controlador (quando se da xterm no mininet) entao dificulta criar uma bridge que conecte o controlador com o switch. -- Pelo menos nao encontrei nas minhas olhadas uma maneira.
#       
#Nesta modelage, estamos criando tudo dentro de um mesmo mininet, por isso tive problemas com a parte de dois controladores no mesmo mininet, mas eh possivel criar duas redes mininet e interliga-las, cada um com o seu controlador. Eh outra abordagem, mas da no mesmo, agr que consegui colocar dois controladores na mesma rede.
#
# obs: na verdade, o root1 sobe o controlador sim !! esta funcionando sem ter esse encaminhamento.
#
#
#   root1--c0              root2--c1
#      \ /                     \  / 
#       s1- - - - - - - - - - - s2
#     /  |  \                    |
#   h1  h2   h3                  h4

def myNet():

    #RYU_controller
    CONTROLLER_IP='127.0.0.1'
#testando ryu controller em um host
#    CONTROLLER_IP_HOST = '172.16.10.1' # assim nao funcionou

    #net = Mininet( topo=None, build=False)
    net = Mininet(topo=None, build=False, link=TCLink, host=CPULimitedHost, switch=OVSKernelSwitch, autoSetMacs=True, ipBase='172.16.10.0/24')

    hosts=5

    # Create nodes
    # h1 = net.addHost( 'h1', mac='8e:49:d6:d3:1e:df', cpu=.5/hosts, ip='172.16.10.1/24')
    # h2 = net.addHost( 'h2', mac='0e:7b:ac:84:a3:69', cpu=.5/hosts, ip='172.16.10.2/24')
    # h3 = net.addHost('h3', mac='ae:f4:cf:ab:4c:15', cpu=.5/hosts, ip='172.16.10.3/24')
    # h4 = net.addHost('h4', mac='b2:2c:c7:c1:72:a4', cpu=.5/hosts, ip='172.16.10.4/24')

    h1 = net.addHost( 'h1', mac='8e:49:d6:d3:1e:df', ip='172.16.10.1/24')
    h2 = net.addHost( 'h2', mac='0e:7b:ac:84:a3:69', ip='172.16.10.2/24')
    h3 = net.addHost('h3', mac='ae:f4:cf:ab:4c:15', ip='172.16.10.3/24')
    h4 = net.addHost('h4', mac='b2:2c:c7:c1:72:a4', ip='172.16.10.4/24')

    # Create switches
    s1 = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:01', dpid='0000000000000001',protocols="OpenFlow10,OpenFlow12,OpenFlow13")
    s2 = net.addSwitch( 's2', listenPort=6635, mac='00:00:00:00:00:02', dpid='0000000000000002',protocols="OpenFlow10,OpenFlow12,OpenFlow13")

    print ("*** Creating links")
    intfh1 = net.addLink(h1, s1, port2=1, bw=15, delay='10ms', loss=0, max_queue_size=1000, use_htb=True).intf1
    intfh2 = net.addLink(h2, s1, port2=2, bw=15, delay='10ms', loss=0, max_queue_size=1000, use_htb=True).intf1
    intfh3 = net.addLink(h3, s1, port2=3, bw=15, delay='10ms', loss=0, max_queue_size=1000, use_htb=True).intf1

    intfh4 = net.addLink(h4, s2, port2=1, bw=15, delay='10ms', loss=0, max_queue_size=1000, use_htb=True).intf1

    net.addLink(s1, s2, port1=4, port2=4, bw=15, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
    

    #Criar um host no root namespace e linkar com o switch -- sobe o controlador, mas os hosts nao enxergam
    root1 = net.addHost('root1', inNamespace=False, ip='10.123.123.1/32')
    intf = net.addLink(s1,root1, port1=5).intf1

    root2 = net.addHost('root2', inNamespace=False, ip='10.123.123.2/32')
    intf = net.addLink(s2,root2, port1=5).intf1
    
    # Add Controllers
    c0= net.addController( 'c0', controller=RemoteController, ip=CONTROLLER_IP, port=7000)

    c1 = net.addController( 'c1', controller=RemoteController, ip=CONTROLLER_IP, port=6699)

    net.build()
    net.start()
 
    #os controladores conhecem apenas os hosts do seu dominio
    root1.cmd( 'route add -host 172.16.10.1 dev root1-eth0')
    root1.cmd( 'route add -host 172.16.10.2 dev root1-eth0')
    root1.cmd( 'route add -host 172.16.10.3 dev root1-eth0')
    root1.cmd( 'arp -s 172.16.10.1 8e:49:d6:d3:1e:df' )
    root1.cmd( 'arp -s 172.16.10.2 0e:7b:ac:84:a3:69' )
    root1.cmd( 'arp -s 172.16.10.3 ae:f4:cf:ab:4c:15' )
    
    #endereco ipv4 ficticio de root1 para root2 (10.123.123.2) - para forcar encaminhar pela interface root2-eth0
    #root1.cmd( 'route add -host 10.123.123.2 dev root1-eth0')
    #root1.cmd( 'arp -s 10.123.123.2 00:00:00:00:00:06' )
    root1.cmd( 'route add -host 10.10.10.2 dev root1-eth0')
    root1.cmd( 'arp -s 10.10.10.2 00:00:00:00:00:06' )

    #controlador c2
    root1.cmd( 'route add -host 20.10.10.2 dev root1-eth0')
    root1.cmd( 'arp -s 20.10.10.2 00:00:00:00:00:06' )

    #os controladores conhecem apenas os hosts do seu dominio
    root2.cmd( 'route add -host 172.16.10.4 dev root2-eth0')
    root2.cmd( 'arp -s 172.16.10.4 b2:2c:c7:c1:72:a4' )

    #endereco ipv4 ficticio de root2 para root1 (10.123.123.1) - para forcar encaminhar pela interface root2-eth0
    #root2.cmd( 'route add -host 10.123.123.1 dev root2-eth0')
    #root2.cmd( 'arp -s 10.123.123.1 00:00:00:00:00:05' )
    root2.cmd( 'route add -host 10.10.10.1 dev root2-eth0')
    root2.cmd( 'arp -s 10.10.10.1 00:00:00:00:00:05' )
    root2.cmd( 'route add -host 20.20.20.1 dev root2-eth0')
    root2.cmd( 'arp -s 20.20.20.1 00:00:00:00:00:05' )

    h1.cmd('route add -host 172.16.10.2 dev h1-eth0')
    h1.cmd('route add -host 172.16.10.3 dev h1-eth0')
    h1.cmd('route add -host 172.16.10.4 dev h1-eth0')
    h1.cmd('route add -host 10.123.123.1 dev h1-eth0')
    h1.cmd('route add -host 10.123.123.2 dev h1-eth0')
    h1.cmd('route add -host 10.10.10.1 dev h1-eth0')
    h1.cmd('route add -host 10.10.10.2 dev h1-eth0')
    #h1.cmd( 'route add -net 10.123.123.0/32 dev ' + str( intfh1 ) )
    h1.cmd('arp -s 172.16.10.2 0e:7b:ac:84:a3:69')
    h1.cmd('arp -s 172.16.10.3 ae:f4:cf:ab:4c:15')
    h1.cmd('arp -s 172.16.10.4 b2:2c:c7:c1:72:a4')
    h1.cmd('arp -s 10.123.123.1 00:00:00:00:00:05')
    h1.cmd('arp -s 10.123.123.2 00:00:00:00:00:06')
    h1.cmd('arp -s 10.10.10.1 00:00:00:00:00:05')
    h1.cmd('arp -s 10.10.10.2 00:00:00:00:00:06')

    h2.cmd('route add -host 172.16.10.1 dev h2-eth0')
    h2.cmd('route add -host 172.16.10.3 dev h2-eth0')
    h2.cmd('route add -host 172.16.10.4 dev h2-eth0')
    h2.cmd('route add -host 10.123.123.1 dev h2-eth0')
    h2.cmd('route add -host 10.123.123.2 dev h2-eth0')
    h2.cmd('route add -host 10.10.10.1 dev h2-eth0')
    h2.cmd('route add -host 10.10.10.2 dev h2-eth0')
    #h2.cmd( 'route add -net 10.123.123.0/32 dev '+ str( intfh2 ) )
    h2.cmd('arp -s 172.16.10.1 8e:49:d6:d3:1e:df')
    h2.cmd('arp -s 172.16.10.3 ae:f4:cf:ab:4c:15')
    h2.cmd('arp -s 172.16.10.4 b2:2c:c7:c1:72:a4')
    h2.cmd('arp -s 10.123.123.1 00:00:00:00:00:05')
    h2.cmd('arp -s 10.123.123.2 00:00:00:00:00:06')
    h2.cmd('arp -s 10.10.10.1 00:00:00:00:00:05')
    h2.cmd('arp -s 10.10.10.2 00:00:00:00:00:06')


    h3.cmd('route add -host 172.16.10.2 dev h3-eth0')
    h3.cmd('route add -host 172.16.10.1 dev h3-eth0')
    h3.cmd('route add -host 172.16.10.4 dev h3-eth0')
    h3.cmd('route add -host 10.123.123.1 dev h3-eth0')
    h3.cmd('route add -host 10.123.123.2 dev h3-eth0')
    h3.cmd('route add -host 10.10.10.1 dev h3-eth0')
    h3.cmd('route add -host 10.10.10.2 dev h3-eth0')
    #h3.cmd( 'route add -net 10.123.123.0/32 dev ' + str( intfh3 ))
    h3.cmd('arp -s 172.16.10.2 0e:7b:ac:84:a3:69')
    h3.cmd('arp -s 172.16.10.1 8e:49:d6:d3:1e:df')
    h3.cmd('arp -s 172.16.10.4 b2:2c:c7:c1:72:a4')
    h3.cmd('arp -s 10.123.123.1 00:00:00:00:00:05')
    h3.cmd('arp -s 10.123.123.2 00:00:00:00:00:06')
    h3.cmd('arp -s 10.10.10.1 00:00:00:00:00:05')
    h3.cmd('arp -s 10.10.10.2 00:00:00:00:00:06')


    h4.cmd('route add -host 172.16.10.2 dev h4-eth0')
    h4.cmd('route add -host 172.16.10.3 dev h4-eth0')
    h4.cmd('route add -host 172.16.10.1 dev h4-eth0')
    h4.cmd('route add -host 10.123.123.1 dev h4-eth0')
    h4.cmd('route add -host 10.123.123.2 dev h4-eth0')
    h4.cmd('route add -host 10.10.10.1 dev h4-eth0')
    h4.cmd('route add -host 10.10.10.2 dev h4-eth0')
    #h4.cmd( 'route add -net 10.123.123.0/32 dev ' + str( intfh4 ) )
    h4.cmd('arp -s 172.16.10.2 0e:7b:ac:84:a3:69')
    h4.cmd('arp -s 172.16.10.3 ae:f4:cf:ab:4c:15')
    h4.cmd('arp -s 172.16.10.1 8e:49:d6:d3:1e:df')
    h4.cmd('arp -s 10.123.123.1 00:00:00:00:00:05')
    h4.cmd('arp -s 10.123.123.2 00:00:00:00:00:06')
    h4.cmd('arp -s 10.10.10.1 00:00:00:00:00:05')
    h4.cmd('arp -s 10.10.10.2 00:00:00:00:00:06')


# Connect each switch to a different controller
    s1.start( [c0] )
    s2.start( [c1] )

    s1.cmdPrint('ovs-vsctl show')
 
    print("\n")

    dumpNodeConnections(net.hosts)

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()
