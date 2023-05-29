# How to test this contrat

> make sure use our modified Dockerfiles instead of SCRAPS's.


## sawtooth network

- `sudo docker-compose -f test.yml up --force-recreate`
    - the validator node should encounter some "command not found" issues
    - go into the validator container `sudo docker exec -it sawtooth-validator-default bash`
    - run this command `sawadm keygen --force && sawtooth keygen my_key --force && sawset genesis -k /root/.sawtooth/keys/my_key.priv && sawadm genesis config-genesis.batch && sawtooth-validator -vv --endpoint tcp://validator:8800 --bind component:tcp://eth0:4004 --bind network:tcp://eth0:8800`
    - then the validator node is up, the whole sawtooth network is up

## registration

- `sudo docker exec -it registration-client bash` go into the registration client
    - `python3 ./registration.py registration` you should see some output like "device is stored"
    - then you can verify this action using `curl http://your_server:8008/state/the_storage_address`

- `sudo docker exec -it attestation-client bash`
    - Attestation Challenge `python3 ./attestation.py challenge 1234 5678`

## attestation

- 一个verifier 5678对三个attester 12341, 12342, 12343进行challenge `python3 ./attestation.py challenge 12341 5678 && python3 ./attestation.py challenge 12342 5678 && python3 ./attestation.py challenge 12343 5678`

- 三个attester返回response`python3 ./attestation.py response 12341 && python3 ./attestation.py response 12342 && python3 ./attestation.py response 12343`

- verifier指定aid进行验证 `python3 ./attestation.py verify 5678 --aidlist 12341 12342 12343`

## audit

- attester上传credential `python3 ./audit.py credential <aid> <vid> --attester`; verifier上传credential `python3 ./audit.py credential <aid> <vid> --verifier`

- participant指定(aid, vid)进行审查 `python3 ./audit.py audit <audit_id> <aid> <vid>`

## turnout

- `sudo docker exec -it turnout-client bash`

- Attester 1234 修改自己的device condition 为 1 `python3 ./turnout.py condition 1234 1`

- Verifier 5678 修改与Attester 1234的Attestation State为1 `python3 ./turnout.py state 5678 1234 1`
