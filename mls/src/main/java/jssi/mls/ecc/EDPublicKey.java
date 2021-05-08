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

package jssi.mls.ecc;

import org.libsodium.api.Crypto_sign_ed25519;
import org.libsodium.jni.SodiumException;

import java.math.BigInteger;
import java.util.Arrays;

public class EDPublicKey implements ECPublicKey {

    private final byte[] publicKey;

    public EDPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public byte[] convert() throws SodiumException {
        return Crypto_sign_ed25519.pk_to_curve25519(publicKey);
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) return false;
        if (!(other instanceof EDPublicKey)) return false;

        EDPublicKey that = (EDPublicKey) other;
        return Arrays.equals(this.publicKey, that.publicKey);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(publicKey);
    }

    @Override
    public int compareTo(ECPublicKey another) {
        return new BigInteger(publicKey).compareTo(new BigInteger(((EDPublicKey) another).publicKey));
    }

    @Override
    public byte[] getBytes() {
        return publicKey;
    }
}
