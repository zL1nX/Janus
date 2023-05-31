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
import janus_attestation_pb2
from time import process_time, sleep


from decimal import Decimal
from colorlog import ColoredFormatter
from attestation_client import AttestationClient

KEY_NAME = 'att_client'

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
    '''Create the command line argument parser for the attestation CLI.'''
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage attestation transaction family via CLI',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True
    
    submit_challenge_subparser = subparsers.add_parser('challenge',
                                           help='submit an attestation challenge nonce',
                                           parents=[parent_parser])
    
    submit_challenge_subparser.add_argument('aid',
                                #type=string,
                                help='attester id')
    
    submit_challenge_subparser.add_argument('vid',
                                #type=string,
                                help='verifier id')
    
    submit_response_subparser = subparsers.add_parser('response',
                                           help='submit an attestation response report',
                                           parents=[parent_parser])
    
    submit_response_subparser.add_argument('aid',
                                #type=string,
                                help='attester id')
    
    request_verify_subparser = subparsers.add_parser('verify',
                                           help='verify specified attestation responses',
                                           parents=[parent_parser])
    
    request_verify_subparser.add_argument('vid',
                                #type=string,
                                help='attester id')
    
    request_verify_subparser.add_argument('--aidlist',
                                nargs="+",
                                help='list of aid')

    return parser


def set_attestation_challenge(args):
    '''Subcommand to submit an attestation evicende.  Calls client class to do submission.'''
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AttestationClient(_base_url=DEFAULT_URL, device_id=args.aid, key_file=privkeyfile)
    nonce = client.generate_nonce()
    payload = construct_attestation_challenge(nonce, args.aid, args.vid)
    response = client.submit_challenge(payload, args.aid)
    print("Set Attestation Challenge: {}".format(response))


def construct_attestation_challenge(nonce, aid, vid):
    encoded_challenge = janus_attestation_pb2.Challenge(
        nonce = nonce,
        aid = aid,
        vid = vid
    ).SerializeToString()
    return encoded_challenge

def set_attestation_response(args):
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AttestationClient(_base_url=DEFAULT_URL, device_id=args.aid, key_file=privkeyfile)
    # check_result = client.query_challenge(args.aid)
    # if is_json(check_result) is False:
    #     LOGGER.info("no challenge yet")
    #     return 0

    # LOGGER.info("Valid Results")
    # challenge_nonce = extract_nonce(check_result)

    challenge_nonce = os.urandom(8)
    print(challenge_nonce)
    encrypted_response = client.generate_encrypted_payload(challenge_nonce)
    att_response = construct_attestation_response(encrypted_response, args.aid)
    response = client.submit_attestation_response(att_response, args.aid)
    print("Set Attestation Response: {}".format(response))
        
    # then submit challenge
    return 1

def construct_attestation_response(content, device_id):
    response = janus_attestation_pb2.Report (
        payload = content,
        aid = device_id
    ).SerializeToString()
    return response


def set_verification_request(args):
    privkeyfile = _get_private_keyfile(KEY_NAME)
    client = AttestationClient(_base_url=DEFAULT_URL, device_id=args.vid, key_file=privkeyfile)
    #print(type(args.aidlist), type(args.aidlist[0])==type(args.vid))
    request = construct_verification_request(args.aidlist, args.vid)
    response = client.submit_verification_request(request, args.aidlist, args.vid)
    print("Verification status: {}".format(response))
    return 1

def construct_verification_request(aidlist, vid):
    vrfy_request = janus_attestation_pb2.Verify (
        vid = vid,
        aid = aidlist
    ).SerializeToString()
    return vrfy_request


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

        if args.command == 'challenge':
            set_attestation_challenge(args)
        elif args.command == 'response':
            set_attestation_response(args)
        elif args.command == 'verify':
            set_verification_request(args)
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
