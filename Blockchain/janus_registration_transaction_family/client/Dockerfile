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
# -----------------------------------------------------------------------------

FROM ubuntu:bionic

ARG DEBIAN_FRONTEND=noninteractive

RUN \
 if [ ! -z $HTTP_PROXY ] && [ -z $http_proxy ]; then \
  http_proxy=$HTTP_PROXY; \
 fi; \
 if [ ! -z $HTTPS_PROXY ] && [ -z $https_proxy ]; then \
  https_proxy=$HTTPS_PROXY; \
 fi; \
 apt-get update \  
 && apt-get install gnupg2 -y

#  echo "deb http://repo.sawtooth.me/ubuntu/ci xenial universe" >> /etc/apt/sources.list \
#  && apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD \
#  && echo "deb [arch=amd64] http://repo.sawtooth.me/ubuntu/bumper/stable xenial universe" >> /etc/apt/sources.list \
RUN echo "deb http://repo.sawtooth.me/ubuntu/nightly bionic universe" >> /etc/apt/sources.list \
 && (apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 44FC67F19B2466EA \
 || apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 44FC67F19B2466EA) \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y -q --no-install-recommends \
    apt-utils \
 && apt-get install -y -q \
    apt-transport-https \
    build-essential \
    ca-certificates \
    inetutils-ping \
    libffi-dev \
    libssl-dev \
    python3-aiodns \
    python3-aiohttp \
    python3-aiopg \
    python3-async-timeout \
    python3-bitcoin \
    python3-cbor \
    python3-cchardet \
    python3-chardet \
    python3-colorlog \
    python3-cov-core \
    python3-cryptography-vectors \
    python3-cryptography \
    python3-dev \
    python3-grpcio-tools \
    python3-grpcio \
    python3-lmdb \
    python3-multidict \
    python3-netifaces \
    python3-nose2 \
    python3-pip \
    python3-protobuf \
    python3-psycopg2 \
    python3-pycares \
    python3-pyformance \
    python3-pytest-runner \
    python3-pytest \
    python3-pytz \
    python3-requests \
    python3-secp256k1 \
    python3-setuptools-scm \
    python3-six \
    python3-toml \
    python3-yaml \
    python3-yarl \
    python3-zmq \
    software-properties-common \
    python3-sawtooth-sdk \
    python3-sawtooth-cli \
 && apt-get clean \
 && pip3 install -U protobuf==3.14.0 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /project/attestation_management/janus_registration_transaction_family/client

ENV PATH "$PATH:/project/attestation_management/janus_registration_transaction_family/client"

EXPOSE 3000

CMD unset PYTHONPATH && python3 setup.py clean --all && python3 setup.py build