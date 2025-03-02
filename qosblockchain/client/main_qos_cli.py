# Copyright 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

from __future__ import print_function

import argparse
import getpass
import logging
import os
import traceback
import sys
import pkg_resources

from colorlog import ColoredFormatter

from qos_client import QoSClient
from qos_exceptions import QoSException

DISTRIBUTION_NAME = 'flowqos'

DEFAULT_URL = 'http://127.0.0.1:8008' # tem que ser passado por parametro


#Modelo transação
# {
#     "name": ""
#     "state": ""
#     "ip_src": ""
#     "ip_dst": ""
#     "src_port": ""
#     "dst_port": ""
#     "proto": ""
#     "qos": ""
#     "freds": ""
# }



def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    if verbose_level == 0:
        clog.setLevel(logging.WARN)
    elif verbose_level == 1:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog


def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


def add_regqos_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'reg_qos',
        help='Creates a transaction for the qos of a flow',
        description='Sends a transaction to register a flow and its qos with the '
        'identifier <flowname>.',
        parents=[parent_parser])

    parser.add_argument(
        'flowname',
        type=str,
        help='unique identifier for the flow')
    
    parser.add_argument(
        'flowjson',
        type=str,
        help='json of the flow and the qos that will be registered')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--disable-client-validation',
        action='store_true',
        default=False,
        help='disable client validation')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for game to commit')


def add_list_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'list',
        help='Displays information for all flows',
        description='Displays information for flows in state, showing '
        'flow information, freds, and qoss for each flow.',
        parents=[parent_parser])

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')


def add_show_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'show',
        help='Displays information about a specific flow',
        description='Displays the flow information <flowname>, showing the flow information, '
        'the freds, and the qoss registered',
        parents=[parent_parser])

    parser.add_argument(
        'flow_name',
        type=str,
        help='identifier for the flow')
    
    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--username',
        type=str,
        help="identify name of user's private key file")

    parser.add_argument(
        '--key-dir',
        type=str,
        help="identify directory of user's private key file")

    parser.add_argument(
        '--auth-user',
        type=str,
        help='specify username for authentication if REST API '
        'is using Basic Auth')

    parser.add_argument(
        '--auth-password',
        type=str,
        help='specify password for authentication if REST API '
        'is using Basic Auth')

def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        help='enable more verbose output')

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to register qos for a flow by sending Flow transactions.',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    subparsers.required = True

    add_regqos_parser(subparsers, parent_parser)
    add_list_parser(subparsers, parent_parser)
    add_show_parser(subparsers, parent_parser)

    return parser

def do_list(args):
    url = _get_url(args)
    auth_user, auth_password = _get_auth_info(args)

    client = QoSClient(base_url=url, keyfile=None)

    flows = [f.decode() for f in client.list(auth_user=auth_user,
                                 auth_password=auth_password)]

    if flows is not None:
        print(flows)
    else:
        raise QoSException("Could not retrieve flow listing.")
    
def do_show(args):
    flow_name = args.flow_name

    url = _get_url(args)
    auth_user, auth_password = _get_auth_info(args)

    client = QoSClient(base_url=url, keyfile=None)

    print('show 1')
    
    data = client.show(flow_name, auth_user=auth_user, auth_password=auth_password)
    
    print('show 2')
    if data is not None:
        print(data)
    else:
        raise QoSException("Flow not found: {}".format(flow_name))


def do_reg_flowqos(args):
    action = args.command
    flow_name = args.flowname
    flow= args.flowjson

    url = _get_url(args)
    keyfile = _get_keyfile(args)
    auth_user, auth_password = _get_auth_info(args)

    client = QoSClient(base_url=url, keyfile=keyfile)

    if args.wait and args.wait > 0:
        response = client.reg_flowqos(
            action, flow, flow_name, wait=args.wait,
            auth_user=auth_user,
            auth_password=auth_password)
    else:
        response = client.reg_flowqos(
            action, flow, flow_name, auth_user=auth_user,
            auth_password=auth_password)

    print("Response: {}".format(response))

def _get_url(args):
    return DEFAULT_URL if args.url is None else args.url


def _get_keyfile(args):
    username = getpass.getuser() if args.username is None else args.username
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.priv'.format(key_dir, username)


def _get_auth_info(args):
    auth_user = args.auth_user
    auth_password = args.auth_password
    if auth_user is not None and auth_password is None:
        auth_password = getpass.getpass(prompt="Auth Password: ")

    return auth_user, auth_password


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)
    print(args)
    if args.verbose is None:
        verbose_level = 0
    else:
        verbose_level = args.verbose

    setup_loggers(verbose_level=verbose_level)

    if args.command == 'reg_qos':
        do_reg_flowqos(args)
    elif args.command == 'list':
        do_list(args)
    elif args.command == 'show':
        do_show(args)
    else:
        raise QoSException("invalid command: {}".format(args.command))

def main_wrapper():
    try:
        main()
    except QoSException as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


### init ####
main_wrapper()