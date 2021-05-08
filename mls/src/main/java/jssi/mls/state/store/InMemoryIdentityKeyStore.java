/*
 *  Copyright 2013 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package jssi.mls.state.store;

import jssi.mls.ProtocolAddress;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.state.IdentityKeyStore;
import jssi.mls.IdentityKey;
import jssi.mls.IdentityKeyPair;
import jssi.resolver.ClientResolver;
import org.bitcoinj.core.Base58;
import uniresolver.ResolutionException;
import uniresolver.result.ResolveResult;

import java.util.HashMap;
import java.util.Map;

public class InMemoryIdentityKeyStore implements IdentityKeyStore {

    private final Map<ProtocolAddress, IdentityKey> trustedKeys = new HashMap<>();
    private final IdentityKeyPair identityKeyPair;
    private final int localRegistrationId;

    public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, int localRegistrationId) {
        this.identityKeyPair = identityKeyPair;
        this.localRegistrationId = localRegistrationId;
    }

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    @Override
    public int getLocalRegistrationId() {
        return localRegistrationId;
    }

    @Override
    public boolean saveIdentity(ProtocolAddress address, IdentityKey identityKey) {
        IdentityKey existing = trustedKeys.get(address);

        if (!identityKey.equals(existing)) {
            trustedKeys.put(address, identityKey);
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean isTrustedIdentity(ProtocolAddress address, IdentityKey identityKey, Direction direction) {

        IdentityKey trusted = trustedKeys.get(address);
        if (trusted == null) {
            return resolve(address, identityKey);
        } else {
            return trusted.equals(identityKey);
        }
    }

    @Override
    public IdentityKey getIdentity(ProtocolAddress address) {
        return trustedKeys.get(address);
    }

    private boolean resolve(ProtocolAddress address, IdentityKey identityKey){
        ClientResolver client = new ClientResolver();
        try {
            ResolveResult result = client.resolve("did:sov:" + address.getDid()).blockingSingle();
            Map method = (Map) result.getDidDocument().getJsonObject().get("verificationMethod");
            String verkey = (String) method.get("publicKeyBase58");
            return Base58.encode(identityKey.getBytes()).equalsIgnoreCase(verkey);
        } catch (ResolutionException e){
            throw new AssertionError(e.getMessage());
        }
    }
}
