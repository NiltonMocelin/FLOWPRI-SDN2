# Como replicar


Esse não está pronto ...

-> rodar o sh setup_5dominios_script


H1: iperf -s 


H2: iperf -c H1


H3: iperf -c H1


H4: iperf -c H1


H5: iperf -c H1



Contar o tempo entre saida e o anuncio da classificacao de tráfego no controlador : 
-> o primeiro pacote é reinjetado na rede pelo flowpri, e as regras BE sao criadas nessa etapa
-> os pacotes do 1 ao 10 são copiados para o flowpri enquanto percorrem as regras BE (eh uma copia, não reinjeta)
-> a partir do 11, em teoria (mas na pratica demora mais de 50), o fluxo é classificado  e novas regras (sem fazer copia para o controlador), são criadas (QoS ou BE) [medir aqui].

10 Vezes é bom;

Média e desvio padrão para 1, 2, 3, 4 saltos (domínios)