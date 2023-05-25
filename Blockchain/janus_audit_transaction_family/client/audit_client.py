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
AuditClient class interfaces with Sawtooth through the REST API.
It accepts input from a client CLI/GUI/BUI or other interface.
'''

import hashlib
import random
import time
import requests
import yaml
import os
import cbor
import logging

from sawtooth_sdk.protobuf import events_pb2
from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

LOGGER = logging.getLogger(__name__)

FAMILY_NAME = 'audit'
JANUS_NONCE_LEN = 8
# TF Prefix is first 6 characters of SHA-512("audit"), 3AD5F1

# Hashing helper method
def _hash(data):
    return hashlib.sha512(data).hexdigest()

def _assembleAddressFromPair(elem1, elem2):
    return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
             _hash(elem1.encode('utf-8'))[0:32] + \
             _hash(elem2.encode('utf-8'))[0:32]

def _assembleAddress(unique_id):
    return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
             _hash(unique_id.encode('utf-8'))[0:64]

class AuditClient(object):
    '''
    Client Audit Manager class handles the the submission of transactions
    Supports "submitEvidence" and "trustQuery" functions.
    '''

    def __init__(self, _base_url, key_file=None):
        '''Initialize the client class
           Mainly getting the key pair and computing the address.
        '''
        self._base_url = _base_url

        if key_file is None:
            self._signer = None
            return

        try:
            with open(key_file) as key_fd:
                private_key_str = key_fd.read().strip()
        except OSError as err:
            raise Exception(
                'Failed to read private key {}: {}'.format(
                    key_file, str(err)))

        try:
            private_key = Secp256k1PrivateKey.from_hex(private_key_str)
        except ParseError as err:
            raise Exception( \
                'Failed to load private key: {}'.format(str(err)))

        self._signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(private_key)
        self._public_key = self._signer.get_public_key().as_hex()


        self._address = _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
            _hash(self._public_key.encode('utf-8'))[0:64]

    def getPublicKey(self):
        return self._public_key

    def submit_audit_credentials(self, credentials, aid, vid):
        storageAddress = _assembleAddressFromPair(aid, vid)
        LOGGER.info('Storage Address %s.',
                storageAddress)
        address_list = [storageAddress] # only need this
        return self._wrap_and_send("submit_audit_credentials", credentials, address_list, address_list, wait=10)

    def submit_audit_request(self, audit_request, audit_id, aid, vid):
        storageAddress = _assembleAddress(audit_id)
        LOGGER.info('Storage Address %s.',
                storageAddress)
        credentials_address = _assembleAddressFromPair(aid, vid)
        input_address_list = ['00b10c00', '00b10c01', storageAddress]
        input_address_list.extend(credentials_address)
        output_address_list = ['00b10c00', '00b10c01', storageAddress]
        result = self._wrap_and_send("submit_audit_request", audit_request, input_address_list, output_address_list, wait=10)
        return result

    def generate_nonce(self):
        return os.urandom(JANUS_NONCE_LEN).hex()

    def _send_to_rest_api(self, suffix, data=None, content_type=None):
        '''Send a REST command to the Validator via the REST API.
        '''
        url = "{}/{}".format(self._base_url, suffix)
        print("URL to send to REST API is {}".format(url))

        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if not result.ok:
                raise Exception("Error {}: {}".format(
                    result.status_code, result.reason))
        except requests.ConnectionError as err:
            raise Exception(
                'Failed to connect to {}: {}'.format(url, str(err)))
        except BaseException as err:
            raise Exception(err)

        return result.text

    def _wait_for_status(self, batch_id, wait, result):
        '''Wait until transaction status is not PENDING (COMMITTED or error).

           'wait' is time to wait for status, in seconds.
        '''
        if wait and wait > 0:
            waited = 0
            start_time = time.time()
            while waited < wait:
                result = self._send_to_rest_api("batch_statuses?id={}&wait={}"
                                                .format(batch_id, wait))
                status = yaml.safe_load(result)['data'][0]['status']
                waited = time.time() - start_time

                if status != 'PENDING':
                    return result
            return "Transaction timed out after waiting {} seconds." \
                .format(wait)
        else:
            return result

    def _wrap_and_send(self, action, data, input_address_list, output_address_list, wait=None):
        '''Create a transaction, then wrap it in a batch.

           Even single transactions must be wrapped into a batch.
           Called by all submission methods.
        '''

        # Assemble an action and the actual payload in a dictionary
        transactionDictionary = {
            'Action': action,
            'Payload': data
        }

        payload = cbor.dumps(transactionDictionary)

        # Create a TransactionHeader.
        header = TransactionHeader(
            signer_public_key=self._public_key,
            family_name=FAMILY_NAME,
            family_version="1.0",
            inputs=input_address_list,
            outputs=output_address_list,
            dependencies=[],
            payload_sha512=_hash(payload),
            batcher_public_key=self._public_key,
            nonce=random.random().hex().encode()
        ).SerializeToString()

        # Create a Transaction from the header and payload above.
        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=self._signer.sign(header)
        )

        transaction_list = [transaction]

        # Create a BatchHeader from transaction_list above.
        header = BatchHeader(
            signer_public_key=self._public_key,
            transaction_ids=[txn.header_signature for txn in transaction_list]
        ).SerializeToString()

        # Create Batch using the BatchHeader and transaction_list above.
        batch = Batch(
            header=header,
            transactions=transaction_list,
            header_signature=self._signer.sign(header))

        # Create a Batch List from Batch above
        batch_list = BatchList(batches=[batch])
        batch_id = batch_list.batches[0].header_signature

        # Send batch_list to the REST API
        result = self._send_to_rest_api("batches",
                                        batch_list.SerializeToString(),
                                        'application/octet-stream')

        # Wait until transaction status is COMMITTED, error, or timed out
        return self._wait_for_status(batch_id, wait, result)
