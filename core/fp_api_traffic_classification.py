import sys

from traffic_classification.classificator import processar_pacotes, classificar_fluxo

def tratador_classificacao_trafego(pkt):

    fred = processar_pacotes(pkt)

    return fred
