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
package jssi.mls.ratchet;

import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPublicKey;
import org.libsodium.jni.SodiumException;
import jssi.mls.InvalidKeyException;
import jssi.mls.kdf.DerivedRootSecrets;
import jssi.mls.kdf.HKDF;
import jssi.mls.util.Pair;

public class RootKey {

    private final HKDF kdf;
    private final byte[] key;

    public RootKey(HKDF kdf, byte[] key) {
        this.kdf = kdf;
        this.key = key;
    }

    public byte[] getKeyBytes() {
        return key;
    }

    public Pair<RootKey, ChainKey> createChain(ECPublicKey theirRatchetKey, ECKeyPair ourRatchetKey) throws InvalidKeyException, SodiumException {
        byte[] sharedSecret = Curve.calculateAgreement(theirRatchetKey, ourRatchetKey.getPrivateKey());
        byte[] derivedSecretBytes = kdf.deriveSecrets(sharedSecret, key, "WhisperRatchet".getBytes(), DerivedRootSecrets.SIZE);
        DerivedRootSecrets derivedSecrets = new DerivedRootSecrets(derivedSecretBytes);

        RootKey newRootKey = new RootKey(kdf, derivedSecrets.getRootKey());
        ChainKey newChainKey = new ChainKey(kdf, derivedSecrets.getChainKey(), 0);

        return new Pair<>(newRootKey, newChainKey);
    }
}
