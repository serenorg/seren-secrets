// Run against the actual nodejs wasm-pack output, not a mock bridge.
// node crates/seren-secrets-crypto-wasm/tests/provisioning.cjs /absolute/path/to/pkg
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const wasm = require(path.resolve(process.argv[2], 'seren_secrets_crypto_wasm.js'));
const fixtures = path.resolve(__dirname, '../../seren-secrets-crypto/tests/fixtures');
const read = name => fs.readFileSync(path.join(fixtures, name), 'utf8').trim();
for (const name of ['legacy', 'provisioning']) {
    const input = read(`${name}-delegation.json`);
    const actual = wasm.agentDelegationContributionPayload(input);
    assert.equal(Buffer.from(actual).toString(), read(`${name}-delegation.payload.json`));
}
const input = JSON.parse(read('provisioning-delegation.json'));
const password = new TextEncoder().encode('synthetic-test-master-password');
const bundle = wasm.accountSetup(password);
const account = wasm.unlockAccount(password, bundle.secretsJson);
const key = account.signingPrivateKey;
try {
    const payload = wasm.agentDelegationContributionPayload(JSON.stringify(input));
    const signature = wasm.agentDelegationContributionSign(key, JSON.stringify(input));
    assert.equal(wasm.verify(bundle.signingPublicKey, payload, signature), true);
    const mutations = [
        c => { c.vault_provisioning.provisioned_vaults[0].adopted = false; },
        c => { c.vault_provisioning.binding.payload_digest = 'cd'.repeat(32); },
        c => { c.vault_provisioning.binding.keys[0] = c.vault_provisioning.provisioned_vaults[0].key = 'changed'; },
        c => { c.vault_grants[0].vault_id = c.vault_provisioning.provisioned_vaults[0].vault_id = '00000000-0000-0000-0000-000000000fff'; },
        c => { c.deployment_id = '00000000-0000-0000-0000-000000000fff'; },
        c => { c.vault_grants[0].wrapped_vault_key = 'AAUG'; },
    ];
    for (const mutate of mutations) {
        const changed = structuredClone(input); mutate(changed);
        assert.equal(wasm.verify(bundle.signingPublicKey, wasm.agentDelegationContributionPayload(JSON.stringify(changed)), signature), false);
    }
    for (const lifetime of ['forever', 'read_only', null]) {
        const changed = structuredClone(input); changed.vault_provisioning.grant_lifetime = lifetime;
        assert.throws(() => wasm.agentDelegationContributionSign(key, JSON.stringify(changed)));
    }
} finally { key.free(); account.free(); bundle.free(); password.fill(0); }
console.log('PASS real WASM legacy/native vectors, provisioning signing and tamper refusal');

const proposal = [{ key: 'opaque', name: 'Fixture vault', description: 'Fixture description', access_level: 'write', source: {kind: '1password', vault_id:'fixture-vault', account_id:'fixture-account'} }];
const binding = JSON.parse(wasm.vaultProvisioningBinding(JSON.stringify(proposal)));
const expectedCanonical = '[{"access_level":"write","description":"Fixture description","key":"opaque","name":"Fixture vault","source":{"account_id":"fixture-account","kind":"1password","vault_id":"fixture-vault"}}]';
assert.equal(binding.payload_digest, require('node:crypto').createHash('sha256').update(expectedCanonical).digest('hex'));
assert.deepEqual(binding.keys, ['opaque']);
assert.throws(() => wasm.vaultProvisioningBinding(JSON.stringify([...proposal, ...proposal])));
console.log('PASS real WASM canonical proposal commitment');
