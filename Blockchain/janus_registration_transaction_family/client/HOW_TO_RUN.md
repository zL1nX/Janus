# How to test this contrat

> make sure use our modified Dockerfiles instead of SCRAPS's.

- `sudo docker-compose -f test.yml up`
    - the validator node should encounter some "command not found" issues
    - go into the validator container `sudo docker exec -it sawtooth-validator-default bash`
    - run this command `sawadm keygen --force && sawtooth keygen my_key && sawset genesis -k /root/.sawtooth/keys/my_key.priv && sawadm genesis config-genesis.batch && sawtooth-validator -vv --endpoint tcp://validator:8800 --bind component:tcp://eth0:4004 --bind network:tcp://eth0:8800`
    - then the validator node is up, the whole sawtooth network is up

- `sudo docker exec -it registration-client bash` go into the registration client
    - `python3 ./registration.py registration`
    - you should see some output like "device is stored"