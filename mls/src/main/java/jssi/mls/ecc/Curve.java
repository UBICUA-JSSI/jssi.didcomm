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

import org.libsodium.api.Crypto_scalarmult;
import org.libsodium.api.Crypto_sign_ed25519;
import org.libsodium.jni.SodiumException;

import jssi.mls.InvalidKeyException;

import java.util.Map;

public class Curve {

    public static ECKeyPair generateKeyPair() throws SodiumException {

        Map<String, byte[]> keyPair = Crypto_sign_ed25519.keypair();

        return new ECKeyPair(new EDPublicKey(keyPair.get("pk")),
                new EDPrivateKey(keyPair.get("sk")));
    }

    public static ECPublicKey getECPublicKey(byte[] bytes)  {
        return new EDPublicKey(bytes);
    }

    public static ECPrivateKey getECPrivateKey(byte[] bytes) {
        return new EDPrivateKey(bytes);
    }

    public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey) throws InvalidKeyException, SodiumException {
        if (publicKey == null) {
            throw new InvalidKeyException("public value is null");
        }

        if (privateKey == null) {
            throw new InvalidKeyException("private value is null");
        }
        return Crypto_scalarmult.curve25519(privateKey.convert(), publicKey.convert());
    }

    public static boolean verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
            throws InvalidKeyException, SodiumException {
        if (signingKey == null || message == null || signature == null) {
            throw new InvalidKeyException("Values must not be null");
        }

        return Crypto_sign_ed25519.verify(message, signature, signingKey.getBytes());
    }

    public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
            throws InvalidKeyException, SodiumException {
        if (signingKey == null || message == null) {
            throw new InvalidKeyException("Values must not be null");
        }

        return Crypto_sign_ed25519.sign(message, signingKey.getBytes());
    }
}
