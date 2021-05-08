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


import jssi.mls.kdf.DerivedMessageSecrets;
import jssi.mls.kdf.HKDF;
import org.libsodium.api.Crypto_auth_hmacsha256;
import org.libsodium.jni.SodiumException;

public class ChainKey {

    private static final byte[] MESSAGE_KEY_SEED = {0x01};
    private static final byte[] CHAIN_KEY_SEED = {0x02};

    private final HKDF kdf;
    private final byte[] key;
    private final int index;

    public ChainKey(HKDF kdf, byte[] key, int index) {
        this.kdf = kdf;
        this.key = key;
        this.index = index;
    }

    public byte[] getKey() {
        return key;
    }

    public int getIndex() {
        return index;
    }

    public ChainKey getNextChainKey() {
        byte[] nextKey = getBaseMaterial(CHAIN_KEY_SEED);
        return new ChainKey(kdf, nextKey, index + 1);
    }

    public MessageKeys getMessageKeys() {
        byte[] inputKeyMaterial = getBaseMaterial(MESSAGE_KEY_SEED);
        byte[] keyMaterialBytes = kdf.deriveSecrets(inputKeyMaterial, "WhisperMessageKeys".getBytes(), DerivedMessageSecrets.SIZE);
        DerivedMessageSecrets keyMaterial = new DerivedMessageSecrets(keyMaterialBytes);

        return new MessageKeys(keyMaterial.getCipherKey(), keyMaterial.getMacKey(), keyMaterial.getIv(), index);
    }

    private byte[] getBaseMaterial(byte[] seed) {
        try {
            return Crypto_auth_hmacsha256.hmacsha256(seed, key);
        } catch (SodiumException e) {
            throw new AssertionError(e);
        }
    }
}
