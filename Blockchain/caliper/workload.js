const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

class AttestationWorkload extends WorkloadModuleBase {
    constructor() {
        super();
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter);
    }

    async submitTransaction() {
        // 构造challenge请求的有效负载
        const challengePayload = {
            action: 'submit_challenge',
            nonce: '12345678',
            aid: '953623c8b388b4459e13f978d7c846f400010003',
            vid: '5678'
        };

        // 构造response请求的有效负载
        const responsePayload = {
            action: 'submit_attestation_response',
            payload: 'encrypted_payload',
            aid: '953623c8b388b4459e13f978d7c846f400010003'
        };

        // 构造verify请求的有效负载
        const verifyPayload = {
            action: 'submit_verification_request',
            vrfy_request: 'verify_request',
            aidlist: ['953623c8b388b4459e13f978d7c846f400010003'],
            vid: '5678'
        };

        // 发送challenge请求
        await this.sutAdapter.sendRequests({
            contractId: 'attestation',
            contractVersion: '1.0',
            contractFunction: 'submit_challenge',
            contractArguments: [JSON.stringify(challengePayload)],
            readOnly: false
        });

        // 发送response请求
        await this.sutAdapter.sendRequests({
            contractId: 'attestation',
            contractVersion: '1.0',
            contractFunction: 'submit_attestation_response',
            contractArguments: [JSON.stringify(responsePayload)],
            readOnly: false
        });

        // 发送verify请求
        await this.sutAdapter.sendRequests({
            contractId: 'attestation',
            contractVersion: '1.0',
            contractFunction: 'submit_verification_request',
            contractArguments: [JSON.stringify(verifyPayload)],
            readOnly: false
        });
    }

    async cleanupWorkloadModule() {
        // 清理工作负载模块
    }
}

function createWorkloadModule() {
    return new AttestationWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;