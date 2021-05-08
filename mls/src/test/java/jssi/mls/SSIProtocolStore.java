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

package jssi.mls;

import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.state.store.InMemoryProtocolStore;
import jssi.mls.state.store.WalletController;
import jssi.mls.util.KeyHelper;
import org.libsodium.jni.SodiumException;

public class SSIProtocolStore extends InMemoryProtocolStore {


    public SSIProtocolStore() throws SodiumException {
        super(generateIdentityKeyPair(), generateRegistrationId());
    }

    public SSIProtocolStore(ProtocolAddress address) throws SodiumException {
        super(generateIdentityKeyPair(address.getDid()), generateRegistrationId());
    }

    private static IdentityKeyPair generateIdentityKeyPair(String did) throws SodiumException {
        WalletController wallet = new WalletController("ubicua_wallet", "ubicua_wallet_key");
        ECKeyPair identity = wallet.findKeyPair(did).blockingSingle();
        return new IdentityKeyPair(new IdentityKey(identity.getPublicKey()), identity.getPrivateKey());
    }

    private static IdentityKeyPair generateIdentityKeyPair() throws SodiumException {
        ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

        return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                identityKeyPairKeys.getPrivateKey());
    }

    private static int generateRegistrationId() {
        return KeyHelper.generateRegistrationId(false);
    }
}
