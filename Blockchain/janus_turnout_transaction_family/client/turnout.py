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
Command line interface for attestation TF.
Parses command line arguments and passes to the attmgr_client class
to process.
'''

import argparse
import logging
import os
import sys
import traceback
import json
import janus_turnout_pb2


from decimal import Decimal
from colorlog import ColoredFormatter
from turnout_client import TurnoutClient, TurnoutType

KEY_NAME = 'turnout'


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


# Assembly of parsers for the transaction commands
def create_parser(prog_name):
    '''Create the command line argument parser for the attestation CLI.'''
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage attestation transaction family via CLI',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True
    
    condition_subparser = subparsers.add_parser('condition',
                                           help='change device conditions',
                                           parents=[parent_parser])
    
    condition_subparser.add_argument('aid',
                                #type=string,
                                help='attester id')
    
    condition_subparser.add_argument('cond',
                                type=int,
                                help='device_condition')
    
    attestation_state_subparser = subparsers.add_parser('state',
                                           help='change attestation state',
                                           parents=[parent_parser])
    
    attestation_state_subparser.add_argument('vid',
                                #type=string,
                                help='verifier id')
    
    attestation_state_subparser.add_argument('aid',
                                #type=string,
                                help='attester id')
    
    attestation_state_subparser.add_argument('state',
                                type=int,
                                help='attestation_state')

    return parser


def set_device_condition(args):
    '''Subcommand to submit an attestation evicende.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = TurnoutClient(_base_url=DEFAULT_URL, device_id=args.aid, key_file=privkeyfile)
    cond = construct_condition(args.aid, args.cond)
    response = client.submit_condition(cond, args.aid)
    print("Set Device Condition: {}".format(response))


def construct_condition(aid, condition):
    cond = janus_turnout_pb2.DeviceCondition(
        device_condition = condition,
        aid = aid
    ).SerializeToString()
    return cond

def set_attestation_state(args):
    '''Subcommand to submit an attestation evicende.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = TurnoutClient(_base_url=DEFAULT_URL, device_id=args.vid, key_file=privkeyfile)
    st = construct_att_state(args.aid, args.vid, args.state)
    response = client.submit_attestation_state(st, args.aid)
    print("Set Attestation State: {}".format(response))


def construct_att_state(aid, vid, state):
    st = janus_turnout_pb2.AttestationState(
        attestation_state = state,
        aid = aid,
        vid = vid
    ).SerializeToString()
    return st

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

        if args.command == 'condition':
            set_device_condition(args)
        elif args.command == 'state':
            set_attestation_state(args)
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
