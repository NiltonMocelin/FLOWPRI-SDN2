#pacotes necessarois para lidar com web
from time import sleep
from eventlet import listen, sleep
from eventlet import wsgi
from eventlet import websocket
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.lib import dpid as dpid_lib

import os, sys

import json

# # Add the parent directory to sys.path
# sys.path.append( os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/flowpri_")
# sys.path.append('../core')

#importando constantes
# from fp_constants import IPC, PORTA_ACCESS_WEB, websocket_conn

PORTA_ACCESS_WEB = 8080 #porta para acessar a pagina web

#base web python - https://github.com/eventlet/eventlet/blob/master/examples/websocket.py

#handle do websocket
@websocket.WebSocketWSGI
def handle(ws):
    """  This is the websocket handler function.  Note that we
    can dispatch based on path in here, too."""

    # websocket_conn = ws
    print('websocket dict:')

    # message_from_client = ws.wait()
    # print(message_from_client)
    print(ws.__dict__)

    if ws.path == '/dados':
        
        snd_json_data = '{ "switches" : [{"nome": "s1","portas": 4},{"nome": "s2","portas": 2},{"nome": "s3","portas": 5}]}'

        # snd_json_data = "texto"

        print(snd_json_data)

        ws.send(snd_json_data)


def get_switches():

    return '{ "switches": [ { "nome": "s1" } ] }'

def get_switch_ports_rules(name):

    return '{ "switches": [ { "nome": "s1" } ] }'

def dispatch(environ, start_response):
    """ This resolves to the web page or the websocket depending on
    the path."""

    print(environ['PATH_INFO'])

    if environ['PATH_INFO'] == '/topology/switches':
        return
    
    if '/get_switch?' in environ['PATH_INFO']:
        # get switch name, buscar todas as regras ativas para cada porta

        switch_name = environ['PATH_INFO'].split('?')[1]
        return 

    if environ['PATH_INFO'] == '/get_switches':
        start_response('200 OK', [('content-type', 'application/json')])
        #responde solicitacao websocket
        
        return get_switches()
    else:
        #responde solicitacao pagina web
        start_response('200 OK', [('content-type', 'text/html')])
        print('Host conectado')
        return [open('wsgiWebSocket/index.html').read()]


def lancar_wsgi():
    print("lancando wsgi ...")
    listener = listen(('127.0.0.1', PORTA_ACCESS_WEB))
    print("\nVisit http://%s:%s/ in your websocket-capable browser.\n" % ("localhost",PORTA_ACCESS_WEB))
    wsgi.server(listener, dispatch)

    print('Feito ...')
