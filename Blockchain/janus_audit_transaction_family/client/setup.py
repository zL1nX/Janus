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
Python package setup (used by Dockerfile).
'''

from setuptools import setup, find_packages

setup(
    name='auditmgr_cli',
    version='1.0',
    description='Sawtooth Audit Manager',
    author='Jens Neureither',
    url='',
    packages=find_packages(),
    install_requires=[
        'aiohttp',
        'colorlog',
        'protobuf',
        'sawtooth-sdk',
        'sawtooth-signing',
        'PyYAML',
    ],
    data_files=[],
    entry_points={
        'console_scripts': [
            'attmgr = auditmgr_cli:main',
        ]
    })

