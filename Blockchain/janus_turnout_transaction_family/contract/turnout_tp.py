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
from time import process_time

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor

import janus_turnout_pb2

FAMILY_NAME = "turnout"
DEFAULT_URL = 'tcp://validator:4004'

LOGGER = logging.getLogger(__name__)


def _hash(data):
    return hashlib.sha512(data).hexdigest()


class TurnoutTransactionHandler(TransactionHandler):

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

        # Get the payload and extract the administration-specific information.
        # Payload needs to be cbor decoded and split into action and actual (inner) payload
        header = transaction.header        
        action, payload = self._decode_transaction(transaction.payload)

        if action == "change_device_condition":
            t = process_time()
            address = handle_device_condition(context, payload)
            LOGGER.info("DC time: %f", process_time() - t)
            LOGGER.info("Devices Address = %s", address)
        elif action == "set_attestation_state":
            t = process_time()
            address = handle_attestation_state(context, payload)
            LOGGER.info("AS time: %f", process_time() - t)
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
def handle_device_condition(context, payload):
    l = janus_turnout_pb2.DeviceCondition()
    l.ParseFromString(payload)

    cond = l.device_condition
    aid = l.aid

    address = _assembleAddress(aid + "condition") # 地址必须与提交时对应, 否则会unauthorized address
    entry = context.get_state([address])
    if len(entry) != 0:
        LOGGER.info('Original Condition is %s', entry[0].data)
    addresses = context.set_state({address: cond.to_bytes(1, "little")})
    LOGGER.info('The Device Condition is stored at address: %s',address)
    return addresses


# Write the device database
def handle_attestation_state(context, payload):
    l = janus_turnout_pb2.AttestationState()
    l.ParseFromString(payload)

    st = l.attestation_state
    aid = l.aid

    address = _assembleAddress(aid + "state") # 地址必须与提交时对应, 否则会unauthorized address
    entry = context.get_state([address])
    if len(entry) != 0:
        LOGGER.info('Original Attestation State is %s', entry[0].data)
    addresses = context.set_state({address: st.to_bytes(1, "little")})
    LOGGER.info('The Attestation State is stored at address: %s',address)
    return addresses

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
        #LOGGER.propagate = False

        # Register the Transaction Handler and start it.
        processor = TransactionProcessor(url=DEFAULT_URL)
        sw_namespace = _hash(FAMILY_NAME.encode('utf-8'))[0:6]
        handler = TurnoutTransactionHandler(sw_namespace)
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
