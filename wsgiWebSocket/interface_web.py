#pacotes necessarois para lidar com web
from time import sleep
from eventlet import listen, sleep
from eventlet import wsgi
from eventlet import websocket

import os, sys

import json

# # Add the parent directory to sys.path
sys.path.append( os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/flowpri_")

#importando constantes
from fp_constants import IPC, PORTA_ACCESS_WEB, websocket_conn

#base web python - https://github.com/eventlet/eventlet/blob/master/examples/websocket.py

#handle do websocket
@websocket.WebSocketWSGI
def handle(ws):
    """  This is the websocket handler function.  Note that we
    can dispatch based on path in here, too."""

    #gambiarrinha do bem, para poder utilizar a conexao quando quiser
    websocket_conn = ws

    message_from_client = ws.wait()
    print(message_from_client)
    # print('websocket dict:')
    # print(ws.__dict__)

    if ws.path == '/dados':
        
        snd_json_data = '{ "switches" : [{"nome": "s1","portas": 4},{"nome": "s2","portas": 2},{"nome": "s3","portas": 5}]}'

        # snd_json_data = "texto"

        print(snd_json_data)

        ws.send(snd_json_data)


def send_dados():

    #limpar os antigos dados
    dados_json = """{
    "dado1": 1,
    "dado2": 2,
    }"""

    return dados_json

def dispatch(environ, start_response):
    """ This resolves to the web page or the websocket depending on
    the path."""

    print(environ['PATH_INFO'])
    if environ['PATH_INFO'] == '/dados':
        #responde solicitacao websocket
        print('websocket')
        return handle(environ, start_response)
    else:
        #responde solicitacao pagina web
        start_response('200 OK', [('content-type', 'text/html')])
        print('Host conectado')
        return [open('../wsgiWebSocket/index.html').read()]


def lancar_wsgi():
    print("lancando wsgi ...")
    listener = listen((IPC, PORTA_ACCESS_WEB))
    print("\nVisit http://%s:%s/ in your websocket-capable browser.\n" % (IPC,PORTA_ACCESS_WEB))
    wsgi.server(listener, dispatch)

    print('Feito ...')
