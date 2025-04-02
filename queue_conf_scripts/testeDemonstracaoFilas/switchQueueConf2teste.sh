#!/bin/bash
#
#	        	Hierarquia esperada Em cada porta
#
#  						 	 Fila principal 100% tamanho link
# 
#                                                                        |
#                                                                        |
#                  ______________________________________________________|___________________________________________________
#                 /            /           |             |               |               |                \                  \
#         	 /	      /            |	         |               |               |                 \                  \
#		/            /             |             |               |               |                  \                  \
#	RealPrio10	RealPrio5      RealPrio2    DadosPrio10	     DadosPrio5      DadosPrio2       BestEfforPrio1      ControlePrio1

#PROBLEMA: So ha uma camada de hieraquia possivel, como fazer tudo funcionar gerenciando com o controlador, vai ser um pouco complicado
# Real = 33% -> vou ter que alocar 33% em cada fila da classe Real e pelo controlador fazer com que as 3 filas nao usem mais que 33% + permitido de enfileiramento -> RealPrio10 = 33%, RealPrio5 = 33%, RealPrio2 = 33%
# 
# O mesmo deve valer para dados 35%
# BestEffort = 25%%
# Controle = 7%
#

#esse rate eh em kbps?bps?
#Bem 20 Mbps -> rate = 20000000


#	      Root/Controlador		 Root/Controlador
#		 |			  |
#		 S1 --------------------- S2
#	      /	 |  \			  |
#	     h1  h2  h3			  h4
#
# s1-eth1 = h1
# s1-eth2 = h2
# s1-eth3 = h3
# s1-eth4 = s2-eth4
# s1-eth5 = root
#
# s2-eth1 = h4
# s2-eth4 = s1-eth4
# s2-eth5 = root

# Q: Faz sentido ter fila em todas as portas ou somente na porta que conecta com o outro switch


##########################################################################################
#

#	OBS: 
#	1 - ANTES DE CONFIGURAR AS FILAS SEMPRE REMOVA AS CONFIGURACOES DA TABELA QOS DO OVSDB, POIS ELA SALVA AS ENTRADAS DE EXPERIMENTOS ANTERIORES
#	ovs-vsctl --all destroy qos
#	ovs-vsctl clear port s1-eth1 qos

#	2 - REMOVER CONFIGURACOES TC QDISC E CLASS PARA A INTERFACE
#	sudo tc qdisc del dev s1-eth1 root

#
####################################################################################


## COMO DEFINIR O TAMANHO DAS FILAS ?? pelo mininet era possivel com ->  direct_qlen

#sera que funciona assim? fila classe1Prio1 = 33% -> BANDA * 0.33, cada vez so altera a BANDA
#export BANDA = 

declare -i BANDA
declare -i CLASS1
declare -i CLASS2
declare -i CLASS3
declare -i CLASS4
declare -i SOMACLASS12
declare -i SOMACLASS12t

BANDA=15000000
CLASS1=4950000
CLASS2=5250000
CLASS3=3750000
CLASS4=1050000
SOMACLASS12=10200000
SOMACLASS12t=10200500

echo "Banda Total=$BANDA, Classe1=$CLASS1, Classe2=$CLASS2, Classe3=$CLASS3, Classe4 $CLASS4"

sudo ovs-vsctl clear port s1-eth4 qos
sudo tc qdisc del dev s1-eth4 root

sudo ovs-vsctl -- set port s1-eth4 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=$BANDA queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- --id=@q0 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12t other-config:priority=10 -- --id=@q1 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12t other-config:priority=5 -- --id=@q2 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12t other-config:priority=2 -- --id=@q3 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12t other-config:priority=10 -- --id=@q4 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12t other-config:priority=5 -- --id=@q5 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12t other-config:priority=2 -- --id=@q6 create queue other-config:min-rate=$CLASS3 other-config:max-rate=$BANDA other-config:priority=10 -- --id=@q7 create queue other-config:min-rate=$CLASS4 other-config:max-rate=$CLASS4 other-config:priority=2


sudo ovs-vsctl clear port s1-eth1 qos
sudo tc qdisc del dev s1-eth1 root

sudo ovs-vsctl -- set port s1-eth1 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=$BANDA queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- --id=@q0 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q1 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q2 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q3 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q4 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q5 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q6 create queue other-config:min-rate=$CLASS3 other-config:max-rate=$BANDA other-config:priority=10 -- --id=@q7 create queue other-config:min-rate=$CLASS4 other-config:max-rate=$CLASS4 other-config:priority=2

sudo ovs-vsctl clear port s1-eth2 qos
sudo tc qdisc del dev s1-eth2 root

sudo ovs-vsctl -- set port s1-eth2 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=$BANDA queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- --id=@q0 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q1 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q2 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q3 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q4 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q5 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q6 create queue other-config:min-rate=$CLASS3 other-config:max-rate=$BANDA other-config:priority=10 -- --id=@q7 create queue other-config:min-rate=$CLASS4 other-config:max-rate=$CLASS4 other-config:priority=2


sudo ovs-vsctl clear port s1-eth3 qos
sudo tc qdisc del dev s1-eth3 root

sudo ovs-vsctl -- set port s1-eth3 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=$BANDA queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- --id=@q0 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q1 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q2 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q3 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q4 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q5 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q6 create queue other-config:min-rate=$CLASS3 other-config:max-rate=$BANDA other-config:priority=10 -- --id=@q7 create queue other-config:min-rate=$CLASS4 other-config:max-rate=$CLASS4 other-config:priority=2



sudo ovs-vsctl clear port s2-eth4 qos
sudo tc qdisc del dev s2-eth4 root


sudo ovs-vsctl -- set port s2-eth4 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=$BANDA queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- --id=@q0 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q1 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q2 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q3 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q4 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q5 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q6 create queue other-config:min-rate=$CLASS3 other-config:max-rate=$BANDA other-config:priority=10 -- --id=@q7 create queue other-config:min-rate=$CLASS4 other-config:max-rate=$CLASS4 other-config:priority=2


sudo ovs-vsctl clear port s2-eth1 qos
sudo tc qdisc del dev s2-eth1 root


sudo ovs-vsctl -- set port s2-eth1 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=$BANDA queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6,7=@q7 -- --id=@q0 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q1 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q2 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q3 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=10 -- --id=@q4 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=5 -- --id=@q5 create queue other-config:min-rate=$SOMACLASS12 other-config:max-rate=$SOMACLASS12 other-config:priority=2 -- --id=@q6 create queue other-config:min-rate=$CLASS3 other-config:max-rate=$BANDA other-config:priority=10 -- --id=@q7 create queue other-config:min-rate=$CLASS4 other-config:max-rate=$CLASS4 other-config:priority=2

