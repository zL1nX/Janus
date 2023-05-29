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
import cbor


from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor

import janus_audit_pb2


DEFAULT_URL = 'tcp://validator:4004'

LOGGER = logging.getLogger(__name__)

FAMILY_NAME = "audit"

ATTESTER_MEASUREMENT = "f05b5bd660c52e61969150db79cf5a887dcb187e04c7bbe542f46152bbb48c2e"
ATTESTER_KS = "75d573976a977ba45df5a17c9d9b0c66"
ATTESTER_KG = "e35c7160ec6385d16ffb6d12e027678b"
VERIFIER_MEASUREMENT = "4558715731e23bad3b8a4599493506c21af7c67c248160119269c5b1de4deb26"
VERIFIER_KS = "b5fbe2160e9a507523818e75351f7076"
VERIFIER_KG = "2733cc6ef145dd9d4fc70fbb95e4c4e7"

def _hash(data):
    return hashlib.sha512(data).hexdigest()

def _calculateCredential(aid, vid, is_attester):
    if is_attester:
        return _hash(_hash(ATTESTER_MEASUREMENT + VERIFIER_MEASUREMENT + aid + vid + VERIFIER_KS) + ATTESTER_KG)
    else:
        return _hash(_hash(ATTESTER_MEASUREMENT + VERIFIER_MEASUREMENT + aid + vid + ATTESTER_KS) + VERIFIER_KG)

class AuditTransactionHandler(TransactionHandler):

    def __init__(self, namespace_prefix):

        self._namespace_prefix = namespace_prefix
        LOGGER.info("Starting audit smart contract")

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
        '''This implements the apply function for the TransactionHandler class.

           The apply function does most of the work for this class by
           processing a transaction for the administration transaction family.
        '''

        # Get the payload and extract the administration-specific information.
        # Payload needs to be cbor decoded and split into action and actual (inner) payload
        header = transaction.header
        action, payload = self._decode_transaction(transaction.payload)

        # Get the signer's public key, sent in the header from the client.
        sender = header.signer_public_key

        # Enable transaction receipts
        b = bytes("adminData", 'utf-8')
        context.add_receipt_data(transaction.payload)

        # Perform the action.
        LOGGER.info("Action = %s.", action)
        LOGGER.info("Payload = %s.", payload)

		# Select the appropriate action

        if action == "submit_audit_credential":
            address = handle_audit_credential(context, payload)
            LOGGER.info("Credentials Address = %s", address)
        elif action == "submit_audit_request":
            address = handle_audit_request(context, payload)
            LOGGER.info("Audit Result Address = %s", address)
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


# Write the credentials database
def handle_audit_credential(context, payload):
    l = janus_audit_pb2.AuditCredential()
    l.ParseFromString(payload)

    credential = l.credential
    address = _assembleAddressFromPair(l.aid, l.vid) # 地址必须与提交时对应, 否则会unauthorized address

    state_entries = context.get_state([address])
    if len(state_entries) != 0:
        LOGGER.info('Attester credential has already been saved at address: %s',
            address)
        credentials = state_entries[0].data
    credentials.append(credential)

    LOGGER.info('Credential is saved at address: %s',
                address)
    addresses = context.set_state({address: credentials})
    LOGGER.info('The Audit Credential is stored')
    return addresses

def handle_verification_request(context, payload):
    l = janus_audit_pb2.AuditRequest()
    l.ParseFromString(payload)

    results = verify_audit_credentials(context, l.aid, l.vid).encode()

    address = _assembleAddress(l.audit_id) # 地址必须与提交时对应, 否则会unauthorized address
    LOGGER.info('Request is saved at address: %s',
                address)
    addresses = context.set_state({address: results})
    LOGGER.info('The Audit Result is stored')

    return addresses

def verify_audit_credentials(context, aid, vid):
    audit_results = {}
    target = _assembleAddressFromPair(aid, vid)
    state_entries = context.get_state([target])
    credentials = state_entries[0].data
    if len(credentials) != 2:
        LOGGER.info('Not enough credentials at address: %s', address)
    print(credentials)
    cr1 = credentials[0]
    cr2 = credentials[1]
    # perform audit here, which should be a double-hash of the reference value `m1||m2||aid||vid`
    # in comparison with the submitted ones
    ref_cr1 = _calculateCredential(aid, vid, is_attester=True)
    ref_cr2 = _calculateCredential(aid, vid, is_attester=False)
    if cr1 == ref_cr1 and cr2 == ref_cr2:
        audit_results[aid + '-' + vid] = True
    else:
        audit_results[aid + '-' + vid] = False
    return json.dumps(audit_results)

# Assemble storage addresses
def _assembleAddress(storage_target):
    return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
             _hash(storage_target.encode('utf-8'))[0:64]

def _assembleAddressFromPair(elem1, elem2):
    return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
             _hash(elem1.encode('utf-8'))[0:32] + \
             _hash(elem2.encode('utf-8'))[0:32]

def main():
    '''Entry-point function for the Audit Transaction Processor.'''
    try:
        # Setup logging for this class.
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)

        # Register the Transaction Handler and start it.
        processor = TransactionProcessor(url=DEFAULT_URL)
        sw_namespace = _hash(FAMILY_NAME.encode('utf-8'))[0:6]
        handler = AuditTransactionHandler(sw_namespace)
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
