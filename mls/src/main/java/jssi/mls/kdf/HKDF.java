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

package jssi.mls.kdf;

import org.libsodium.api.Crypto_auth;
import org.libsodium.jni.SodiumException;

import java.io.ByteArrayOutputStream;

import static org.libsodium.jni.SodiumConstants.CRYPTO_AUTH_HMACSHA256_KEYBYTES;

public class HKDF {

    public HKDF() {
    }

    public byte[] deriveSecrets(byte[] data, byte[] info, int outputLength) {
        byte[] key = new byte[CRYPTO_AUTH_HMACSHA256_KEYBYTES];
        return deriveSecrets(data, key, info, outputLength);
    }

    public byte[] deriveSecrets(byte[] data, byte[] key, byte[] info, int outputLength) {
        byte[] prk = extract(key, data);
        return expand(prk, info, outputLength);
    }

    private byte[] extract(byte[] key, byte[] data) {
        try {
            return Crypto_auth.hmacsha256(data, key);
        } catch (SodiumException e) {
            throw new AssertionError(e);
        }
    }

    private byte[] expand(byte[] prk, byte[] info, int outputSize) {
        try {
            int iterations = (int) Math.ceil((double) outputSize / (double) CRYPTO_AUTH_HMACSHA256_KEYBYTES);
            byte[] mixin = new byte[0];
            ByteArrayOutputStream results = new ByteArrayOutputStream();
            int remainingBytes = outputSize;

            for (int i = 1; i < iterations + 1; i++) {
                byte[] state = Crypto_auth.hmacsha256_init(prk);

                Crypto_auth.hmacsha256_update(state, mixin);
                if (info != null) {
                    Crypto_auth.hmacsha256_update(state, info);
                }
                Crypto_auth.hmacsha256_update(state, new byte[]{(byte) i});
                byte[] stepResult = Crypto_auth.hmacsha256_final(state);

                int stepSize = Math.min(remainingBytes, stepResult.length);
                results.write(stepResult, 0, stepSize);

                mixin = stepResult;
                remainingBytes -= stepSize;
            }

            return results.toByteArray();
        } catch (SodiumException e) {
            throw new AssertionError(e);
        }
    }
}
