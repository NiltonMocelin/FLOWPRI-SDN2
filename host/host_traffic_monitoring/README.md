# Ferramenta de captura de pacotes - libpcap python

- Objetivo: Capturar pacotes que contenham uma cerca marcação no campo de cabeçalho IPv6 traffic label

- Metodologia: 

1 monitorar o trafego de uma interface de rede e armazenar todos os pacotes marcados em um arquivo pcap ou em uma lista (objetivo)

2 quando contar 20 pacotes marcados, coletar estatísticas de QoS


