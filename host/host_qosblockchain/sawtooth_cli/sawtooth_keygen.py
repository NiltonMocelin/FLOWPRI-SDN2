# Copyright 2016 Intel Corporation
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

import getpass
import os
import sys
import logging
import argparse
from colorlog import ColoredFormatter
import pkg_resources

from host.host_qosblockchain.sawtooth_cli.admin_command.sawtooth_signing1 import create_context
from host.host_qosblockchain.sawtooth_cli.exceptions import CliException
from host.host_qosblockchain.sawtooth_cli.cli_config import load_cli_config

DISTRIBUTION_NAME = 'sawtooth-cli'

def add_keygen_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'keygen',
        help='Creates user signing keys',
        description='Generates keys with which the user can sign '
        'transactions and batches.',
        epilog='The private and public key files are stored in '
        '<key-dir>/<key-name>.priv and <key-dir>/<key-name>.pub. '
        '<key-dir> defaults to ~/.sawtooth and <key-name> defaults to $USER.',
        parents=[parent_parser])

    parser.add_argument(
        'key_name',
        help='specify the name of the key to create',
        nargs='?')

    parser.add_argument(
        '--key-dir',
        help="specify the directory for the key files")

    parser.add_argument(
        '--force',
        help="overwrite files if they exist",
        action='store_true')

    parser.add_argument(
        '-q',
        '--quiet',
        help="do not display output",
        action='store_true')
    

def main(prog_name=os.path.basename(sys.argv[0]), args=None,
         with_loggers=True):
    parser = create_parser(prog_name)
    if args is None:
        args = sys.argv[1:]
    args = parser.parse_args(args)

    load_cli_config(args)

    if with_loggers is True:
        if args.verbose is None:
            verbose_level = 0
        else:
            verbose_level = args.verbose
        setup_loggers(verbose_level=verbose_level)

    if args.command == 'keygen':
        do_keygen(args)
    else:
        raise CliException("invalid command: {}".format(args.command))



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
        version=(DISTRIBUTION_NAME + ' (Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to configure, manage, '
        'and use Sawtooth components.',
        parents=[parent_parser],)

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True

    add_keygen_parser(subparsers, parent_parser)

    return parser

def do_keygen(args):
    if args.key_name is not None:
        key_name = args.key_name
    else:
        key_name = getpass.getuser()

    if args.key_dir is not None:
        key_dir = args.key_dir
        if not os.path.exists(key_dir):
            raise CliException('no such directory: {}'.format(key_dir))
    else:
        key_dir = os.path.join(os.path.expanduser('~'), '.sawtooth', 'keys')
        if not os.path.exists(key_dir):
            if not args.quiet:
                print('creating key directory: {}'.format(key_dir))
            try:
                os.makedirs(key_dir, 0o755)
            except IOError as e:
                raise CliException('IOError: {}'.format(str(e))) from e

    print("file name: ", key_dir, key_name + '.priv')
    priv_filename = os.path.join(key_dir, key_name + '.priv')
    pub_filename = os.path.join(key_dir, key_name + '.pub')

    if not args.force:
        file_exists = False
        for filename in [priv_filename, pub_filename]:
            if os.path.exists(filename):
                file_exists = True
                print('file exists: {}'.format(filename), file=sys.stderr)
        if file_exists:
            raise CliException(
                'files exist, rerun with --force to overwrite existing files')

    context = create_context('secp256k1')
    private_key = context.new_random_private_key()
    public_key = context.get_public_key(private_key)

    try:
        priv_exists = os.path.exists(priv_filename)
        with open(priv_filename, 'w') as priv_fd:
            if not args.quiet:
                if priv_exists:
                    print('overwriting file: {}'.format(priv_filename))
                else:
                    print('writing file: {}'.format(priv_filename))
            priv_fd.write(private_key.as_hex())
            priv_fd.write('\n')
            # Set the private key u+rw g+r
            os.chmod(priv_filename, 0o640)

        pub_exists = os.path.exists(pub_filename)
        with open(pub_filename, 'w') as pub_fd:
            if not args.quiet:
                if pub_exists:
                    print('overwriting file: {}'.format(pub_filename))
                else:
                    print('writing file: {}'.format(pub_filename))
            pub_fd.write(public_key.as_hex())
            pub_fd.write('\n')
            # Set the public key u+rw g+r o+r
            os.chmod(pub_filename, 0o644)

    except IOError as ioe:
        raise CliException('IOError: {}'.format(str(ioe))) from ioe

