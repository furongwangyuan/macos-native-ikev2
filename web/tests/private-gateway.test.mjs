import test from 'node:test';
import assert from 'node:assert/strict';
import {privateGatewayConfigured} from '../lib/private-gateway.mjs';
test('Worker opt-in is false by default; this is not static-asset authentication',()=>{
 for(const env of [undefined,{}, {FAMILY_VPN_PRIVATE_SITES_DEPLOYMENT:'true'}]) assert.equal(privateGatewayConfigured(env),false);
 assert.equal(privateGatewayConfigured({},true),true);
 assert.equal(privateGatewayConfigured({FAMILY_VPN_PRIVATE_SITES_DEPLOYMENT:'owner-private-confirmed'}),true);
});
