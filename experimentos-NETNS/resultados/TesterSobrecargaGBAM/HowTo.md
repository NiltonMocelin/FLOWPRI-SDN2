# Como replicar

-> rodar o sh setup_5dominios_script

Não sei se faz sentido essa combinatória ou se fazer apenas um cenário seria bom.

tcpdump h1
tcpdump h2
H1: iperf -s 
H2: iperf -c H1 * 2, 10, 30

tcpdump h1
tcpdump h3
H3: iperf -c H1 * 2 , 10, 30

tcpdump h1
tcpdump h4
H4: iperf -c H1 * 2, 10, 30

tcpdump h1
tcpdump h5
H5: iperf -c H1 * 2, 10, 30


Primeiro cenário:
Todos são BE, escalar e ver quantos pacotes o são entregues em 30 segundos

Segundo cenário:
O fluxo de h5 é QoS com garantia e meter 2mb -- problema que não podem ter 30 *2 = 60mb, se o link suporta apenas 50 -- ver melhor esse


Objetivo: Mostrar o ganho percebido utilizando o GBAM

10 Vezes é bom;

Média e desvio padrão para 1, 2, 3, 4 saltos (domínios)