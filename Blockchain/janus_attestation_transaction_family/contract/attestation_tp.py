#!/usr/bin/env python3

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
AdministrationTransactionHandler class interfaces for Administration Transaction Family.
'''

import traceback
import sys
import hashlib
import json
import logging
from time import process_time
import cbor
from Crypto.Cipher import AES
from Crypto.Util import Counter

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing.secp256k1 import Secp256k1PublicKey

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor

import janus_attestation_pb2


DEFAULT_URL = 'tcp://validator:4004'

LOGGER = logging.getLogger(__name__)

FAMILY_NAME = "attestation"
G_HASH_MEASUREMENT = b'\xf0[[\xd6`\xc5.a\x96\x91P\xdby\xcfZ\x88}\xcb\x18~\x04\xc7\xbb\xe5B\xf4aR\xbb\xb4\x8c.'
ATT_COMM_KEY = b'u\xd5s\x97j\x97{\xa4]\xf5\xa1|\x9d\x9b\x0cf'
ATT_PUBKEY = b'\x02\x86\xb1\xaaQ \xf0yYCH\xc6vGg\x9ez\xc4\xc3e\xb2\xc0\x130\xdbx+\x0b\xa6\x11\xc1\xd6w'

def _hash(data):
    return hashlib.sha512(data).hexdigest()


class AttestationTransactionHandler(TransactionHandler):

    def __init__(self, namespace_prefix):

        self._namespace_prefix = namespace_prefix
        LOGGER.info("Starting attestation smart contract")

    @property
    def family_name(self):
        '''Return Transaction Family name string.'''
        return FAMILY_NAME

    @property
    def family_versions(self):
        '''Return Transaction Family version string.'''
        return ['1.0']

    @property
    def namespaces(self):
        '''Return Transaction Family namespace 6-character prefix.'''
        return [self._namespace_prefix]

    def apply(self, transaction, context):

        header = transaction.header        
        action, payload = self._decode_transaction(transaction.payload)

        context.add_receipt_data(transaction.payload)

        # Perform the action.
        LOGGER.info("Action = %s.", action)
        LOGGER.info("Payload = %s.", payload)
		
		# Select the appropriate action

        if action == "submit_challenge":
            address = handle_attestation_challenge(context, payload)
            LOGGER.info("Devices Address = %s", address)
        elif action == "submit_attestation_response":
            t = process_time()
            address = handle_attestation_response(context, payload)
            LOGGER.info("response time %f", process_time() - t)
        elif action == "submit_verification_request":
            t = process_time()
            address = handle_verification_request(context, payload)
            LOGGER.info("verify time %f", process_time() - t)
        else:
            LOGGER.info("Unhandled action. Action not legal!")

    # Handle transaction decoding
    def _decode_transaction(self, payload):
        try:
            content = cbor.loads(payload)
        except:
            raise InvalidTransaction('Invalid payload serialization')

        try:
            action = content['Action']
        except AttributeError:
            raise InvalidTransaction('Action must be here')

        try:
            payload = content['Payload']
        except AttributeError:
            raise InvalidTransaction('Payload must be here')

        return action, payload


# Write the device database
def handle_attestation_challenge(context, payload):
    l = janus_attestation_pb2.Challenge()
    l.ParseFromString(payload)

    challenge_nonce = bytes.fromhex(l.nonce) # set_state expects bytes 
    aid = l.aid

    address = _assembleAddress(aid) # 地址必须与提交时对应, 否则会unauthorized address
    LOGGER.info('Nonce are saved at address: %s',
                address)
    addresses = context.set_state({address: challenge_nonce})
    LOGGER.info('The Attestation Challenge Nonce is stored')
    return addresses

# Write the device database
def handle_attestation_response(context, payload):
    l = janus_attestation_pb2.Report()
    l.ParseFromString(payload)

    report = bytes.fromhex(l.payload) # set_state expects bytes 
    aid = l.aid

    address = _assembleAddress(aid) # 地址必须与提交时对应, 否则会unauthorized address
    LOGGER.info('Report are saved at address: %s',
                address)
    addresses = context.set_state({address: report})
    LOGGER.info('The Attestation Report is stored')
    return addresses

def handle_verification_request(context, payload):
    l = janus_attestation_pb2.Verify()
    l.ParseFromString(payload)

    print(type(l.aid))
    results = verify_response(context, l.aid).encode()

    address = _assembleAddress(l.vid) # 地址必须与提交时对应, 否则会unauthorized address
    LOGGER.info('Request is saved at address: %s',
                address)
    addresses = context.set_state({address: results})
    LOGGER.info('The Verification Results is stored')

    return addresses

def verify_response(context, aidlist):
    verify_results = {}
    for id in aidlist:
        LOGGER.info(id)
        target = _assembleAddress(id)
        state_entries = context.get_state([target])
        if state_entries == []:
            LOGGER.info('No report for %s', id)
            continue
        print(state_entries[0].data)
        verify_results[id] = verify_measurement(state_entries[0].data, id)
         # perform verification here
    return json.dumps(verify_results)

def verify_measurement(cipher_bytes, aid):
    counter = Counter.new(128)
    test_cipher = AES.new(ATT_COMM_KEY, AES.MODE_CTR, counter=counter)
    test_plain = test_cipher.decrypt(cipher_bytes[8:])
    meas, test_sig = test_plain[8:24], test_plain[24:]

    context = create_context('secp256k1')
    result = context.verify(test_sig, meas, Secp256k1PublicKey.from_bytes(ATT_PUBKEY))
    if result is False:
        LOGGER.info("Signature Invalid")
        return result
    LOGGER.info(aid)
    result = (hashlib.sha256(meas + aid.encode() + b'\xff').digest() == G_HASH_MEASUREMENT)
    if result is False:
        LOGGER.info("Measurement Invalid")
        return result

    LOGGER.info("Attestation Passed")
    return result

# Assemble storage addresses
def _assembleAddress(storage_target):

    return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
             _hash(storage_target.encode('utf-8'))[0:64]

def main():
    '''Entry-point function for the Administration Transaction Processor.'''
    try:
        # Setup logging for this class.
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)

        # Register the Transaction Handler and start it.
        processor = TransactionProcessor(url=DEFAULT_URL)
        sw_namespace = _hash(FAMILY_NAME.encode('utf-8'))[0:6]
        handler = AttestationTransactionHandler(sw_namespace)
        processor.add_handler(handler)
        processor.start()
    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
