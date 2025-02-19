
from time import sleep
import eventlet
from eventlet import wsgi
from eventlet import websocket
# from threading import Thread
# import six

# demo app
import os
# import random


#################################
# comunicacao interface web x controlador

# PORTA_WEBS_RCV = 9998 #porta para receber solicitacoes de informacoes JSON para a interface WEB
# PORTA_WEBS_SND = 9997 #porta para enviar informacoes JSON para a interface WEB
# PORTA_ACCESS_WEB = 7000
# __IP = '172.17.0.2'


PORTA_WEBS_RCV = 9971 #porta para receber solicitacoes de informacoes JSON para a interface WEB
PORTA_WEBS_SND = 9972 #porta para enviar informacoes JSON para a interface WEB
PORTA_ACCESS_WEB = 9970

__IP = 'localhost'


dados_json = ''

# try :
#     import psutil 
# except ImportError:
#     print("instalar psutil")
    
import json

def pc_status():
    """Obtem a carga de cpu atual e a ram utilizada e monta um json"""
    # Getting all memory using os.popen()
    # print(os.popen('free -t -m'))

    total_memory, used_memory, free_memory = os.popen('free -m').readlines()[-1].split()[1:]

    # cpu_utilization = psutil.cpu_percent()

    # status_js = """{
    #             "controller_stats":[ {
    #                     "total_memory":%s
    #                 },
    #                 {
    #                     "used_memory":%s
    #                 },
    #                 {
    #                     "free_memory":%s
    #                 },
    #                 {
    #                     "cpu_utilization":%s
    #                 }
    #             ]}""" % (total_memory, used_memory, free_memory, cpu_utilization)

    status_js = """Ola"""

    return status_js


#__IP='localhost'
def _websocket_rcv(json_request):
    """ Socket para receber solicitacoes a interface websocket """
    
    json_reply = """{
        "reply":[
            ["algo1": "valor1"],
            ["algo2": "valor2"]
            ]
        }"""

    return json_reply

def _websocket_snd(ws, dados_json):
    """ Socket para enviar informacoes a interface websocket """

    ws.send(dados_json)

###################################

@websocket.WebSocketWSGI
def handle(ws):
    """  This is the websocket handler function.  Note that we
    can dispatch based on path in here, too."""
    print('entrou no handle: ', ws.path)

    if ws.path == '/echo':
        while True:
            m = ws.wait()
            if m is None:
                break
            ws.send(m)

def send_dados():

    # dados_json2 = dados_json

    #limpar os antigos dados
    # dados_json = ''

    return pc_status()


def dispatch(environ, start_response):
    """ This resolves to the web page or the websocket depending on
    the path."""

    print(environ['PATH_INFO'])
    if environ['PATH_INFO'] == '/dados':
        start_response('200 OK', [('content-type', 'text/html')])
        print('AAAAA')
        return send_dados()
    else:
        start_response('200 OK', [('content-type', 'text/html')])
        print('Host conectado')
        return [open('wsgiWebSocket/index.html').read()]

def lancar_wsgi():
    print("lancando wsgi ...")
    listener = eventlet.listen((__IP, PORTA_ACCESS_WEB))
    print("\nVisit http://%s:%s/ in your websocket-capable browser.\n" % (__IP,PORTA_ACCESS_WEB))
    wsgi.server(listener, dispatch)

    print('Feito ...')
