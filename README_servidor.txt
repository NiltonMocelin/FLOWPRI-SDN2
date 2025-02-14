# Funcoes -- Formato mensagem json:

{
        'regras':{
            ['switch_id':'1', 'tipo_regra':'adicionar'...],
            ['switch_id': '1', 'tipo_regra':'remover'....]
        },

        'add_switch':{

            ['switch_id': '1','sla': 'asda'....]
        }
    }


* add_switch
    



* del_switch



* add_rota
        nome_switch = rota['switch_id']
        prefixo = rota['prefixo_rede']
        mascara = rota['mascara_rede']
        tipo = rota['tipo'] # adicionar rota/remover rota

        porta_saida = rota['porta_saida']


* del_rota
        nome_switch = rota['switch_id']
        prefixo = rota['prefixo_rede']
        mascara = rota['mascara_rede']
        tipo = rota['tipo'] # adicionar rota/remover rota

        porta_saida = rota['porta_saida']


* add_regra
    
        nome_switch = regra['switch_id']
        tipo_regra = regra['tipo_regra']
        ip_src = regra['ip_src']
        ip_dst = regra['ip_dst']
        porta_switch = regra['porta_switch']
        porta_destino = regra['porta_destino']
        porta_origem = regra['porta_origem]
        proto = regra['proto']
        #isso vai ser modificado outro momento
        classe = regra['classe']
        prioridade = regra['prioridade']
        banda = regra['banda']

* del_regra
        nome_switch = regra['switch_id']
        tipo_regra = regra['tipo_regra']
        ip_src = regra['ip_src']
        ip_dst = regra['ip_dst']
        porta_switch = regra['porta_switch']
        porta_destino = regra['porta_destino']
        porta_origem = regra['porta_origem]
        proto = regra['proto']
