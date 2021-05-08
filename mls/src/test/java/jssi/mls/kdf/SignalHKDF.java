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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.libsodium.jni.SodiumConstants.CRYPTO_AUTH_HMACSHA256_KEYBYTES;

public class SignalHKDF {

    private static final Logger LOG = LoggerFactory.getLogger(HKDF.class);

    public SignalHKDF(){}

    public byte[] deriveSecrets(byte[] ikm, byte[] info, int outputLength) {
        byte[] salt = new byte[CRYPTO_AUTH_HMACSHA256_KEYBYTES];
        return deriveSecrets(ikm, salt, info, outputLength);
    }

    public byte[] deriveSecrets(byte[] ikm, byte[] salt, byte[] info, int outputLength) {
        LOG.debug(String.format("Salt size: %d", salt.length));
        byte[] prk = extract(salt, ikm);
        return expand(prk, info, outputLength);
    }

    private byte[] extract(byte[] salt, byte[] ikm) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            return mac.doFinal(ikm);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
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
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));

                mac.update(mixin);
                if (info != null) {
                    mac.update(info);
                }
                mac.update((byte) i);

                byte[] stepResult = mac.doFinal();
                int stepSize = Math.min(remainingBytes, stepResult.length);

                results.write(stepResult, 0, stepSize);

                mixin = stepResult;
                remainingBytes -= stepSize;
            }

            return results.toByteArray();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
}
