#!/usr/bin/env python3

# Copyright 2018 Intel Corporation
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
#
# Parts of code and comments contained in this file are taken from
# the official Hyperledger Sawtooth documentation
# https://sawtooth.hyperledger.org/docs/core/releases/1.1.4/contents.html
# and from example projects from developer ``danintel'':
# https://github.com/danintel/sawtooth-cookiejar
#
'''
Command line interface for audit TF.
Parses command line arguments and passes to the audit_client class
to process.
'''

import argparse
import logging
import os
import sys
import traceback
import json
import janus_audit_pb2


from decimal import Decimal
from colorlog import ColoredFormatter
from audit_client import AuditClient

KEY_NAME = 'audit'

# hard-coded for simplicity (otherwise get the URL from the args in main):
#DEFAULT_URL = 'http://localhost:8008'

DEFAULT_URL = 'http://rest-api:8008'

# Initialize logger
LOGGER = logging.getLogger(__name__)

# Initialize console
def create_console_handler(verbose_level):
    '''Setup console logging.'''
    del verbose_level # unused
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
    clog.setLevel(logging.DEBUG)
    return clog

# Logger setup
def setup_loggers(verbose_level):
    '''Setup logging.'''
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))

def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError as e:
        return False
    return True

def extract_nonce(ss):
    data = json.loads(ss)
    print(data["data"])
    return data["data"]


# Assembly of parsers for the transaction commands
def create_parser(prog_name):
    '''Create the command line argument parser for the audit CLI.'''
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage audit transaction family via CLI',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True

    submit_credentials_subparser = subparsers.add_parser('credentials',
                                           help='submit audit credential pairs',
                                           parents=[parent_parser])

    submit_credentials_subparser.add_argument('cr1',
                                #type=string,
                                help='credential 1')

    submit_credentials_subparser.add_argument('cr2',
                                #type=string,
                                help='credential 2')

    submit_challenge_subparser.add_argument('aid',
                                #type=string,
                                help='attester id')

    submit_challenge_subparser.add_argument('vid',
                                #type=string,
                                help='verifier id')

    credential_audit_subparser = subparsers.add_parser('audit',
                                           help='audit credentials of the specified aid and vid',
                                           parents=[parent_parser])

    credential_audit_subparser.add_argument('audit_id',
                                #type=string,
                                help='audit id')

    credential_audit_subparser.add_argument('aid',
                                #type=string,
                                help='attester id')

    credential_audit_subparser.add_argument('vid',
                                #type=string,
                                help='verifier id')

    return parser


def set_audit_credentials(args):
    '''Subcommand to submit a pair of credentials.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AuditClient(_base_url=DEFAULT_URL, key_file=privkeyfile)
    nonce = client.generate_nonce()
    payload = construct_audit_credentials(nonce, args.cr1, args.cr2, args.aid, args.vid)
    response = client.submit_audit_credentials(payload, args.aid)
    print("Set Audit Credentials: {}".format(response))

def construct_audit_credentials(nonce, cr1, cr2, aid, vid):
    encoded_challenge = janus_audit_pb2.Credentials(
        nonce = nonce,
        credential1 = cr1,
        credential2 = cr2,
        aid = aid,
        vid = vid
    ).SerializeToString()
    return encoded_challenge

def set_audit_request(args):
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AuditClient(_base_url=DEFAULT_URL, key_file=privkeyfile)
    request = construct_audit_request(args.audit_id, args.aid, args.vid)
    response = client.submit_audit_request(request, args.audit_id, args.aid, args.vid)
    print("Audit status: {}".format(response))
    return 1

def construct_audit_request(audit_id, aid, vid):
    audit_request = janus_audit_pb2.AuditRequest (
        audit_id = audit_id,
        aid = aid,
        vid = vid
    ).SerializeToString()
    return audit_request

# Load the private keyfile
def _get_private_keyfile(key_name):
    '''Get the private key for key_name.'''
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, key_name)

def main(prog_name=os.path.basename(sys.argv[0]), args=None):

    try:
        parser = create_parser(prog_name)
        args = parser.parse_args(args)
        verbose_level = 0
        setup_loggers(verbose_level=verbose_level)

        if args.command == 'credentials':
            set_audit_credentials(args)
        elif args.command == 'audit':
            set_audit_request(args)
        else:
            raise Exception("Invalid command: {}".format(args.command))

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
