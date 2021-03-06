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
package jssi.mls.util;

import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.EDPublicKey;
import org.libsodium.jni.SodiumException;
import jssi.mls.IdentityKey;
import jssi.mls.IdentityKeyPair;
import jssi.mls.InvalidKeyException;
import jssi.mls.state.PreKeyRecord;
import jssi.mls.state.SignedPreKeyRecord;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;

/**
 * Helper class for generating keys of different types.
 *
 * @author Moxie Marlinspike
 */
public class KeyHelper {

    private KeyHelper() {
    }

    /**
     * Generate an identity key pair.  Clients should only do this once,
     * at install time.
     *
     * @return the generated IdentityKeyPair.
     */
    public static IdentityKeyPair generateIdentityKeyPair() throws SodiumException {
        ECKeyPair keyPair = Curve.generateKeyPair();
        IdentityKey publicKey = new IdentityKey(keyPair.getPublicKey());
        return new IdentityKeyPair(publicKey, keyPair.getPrivateKey());
    }

    /**
     * Generate a registration ID.  Clients should only do this once,
     * at install time.
     *
     * @param extendedRange By default (false), the generated registration
     *                      ID is sized to require the minimal possible protobuf
     *                      encoding overhead. Specify true if the caller needs
     *                      the full range of MAX_INT at the cost of slightly
     *                      higher encoding overhead.
     * @return the generated registration ID.
     */
    public static int generateRegistrationId(boolean extendedRange) {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            if (extendedRange) return secureRandom.nextInt(Integer.MAX_VALUE - 1) + 1;
            else return secureRandom.nextInt(16380) + 1;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    public static int getRandomSequence(int max) {
        try {
            return SecureRandom.getInstance("SHA1PRNG").nextInt(max);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Generate a list of PreKeys.  Clients should do this at install time, and
     * subsequently any time the list of PreKeys stored on the server runs low.
     * <p>
     * PreKey IDs are shorts, so they will eventually be repeated.  Clients should
     * store PreKeys in a circular buffer, so that they are repeated as infrequently
     * as possible.
     *
     * @param start The starting PreKey ID, inclusive.
     * @param count The number of PreKeys to generate.
     * @return the list of generated PreKeyRecords.
     */
    public static List<PreKeyRecord> generatePreKeys(int start, int count) throws SodiumException {
        List<PreKeyRecord> results = new LinkedList<>();

        start--;

        for (int i = 0; i < count; i++) {
            results.add(new PreKeyRecord(((start + i) % (Medium.MAX_VALUE - 1)) + 1, Curve.generateKeyPair()));
        }

        return results;
    }

    /**
     * Generate a signed PreKey
     *
     * @param identityKeyPair The local client's identity key pair.
     * @param signedPreKeyId The PreKey id to assign the generated signed PreKey
     *
     * @return the generated signed PreKey
     * @throws InvalidKeyException when the provided identity key is invalid
     */
    public static SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKeyPair, int signedPreKeyId)
            throws InvalidKeyException, SodiumException {
        ECKeyPair keyPair = Curve.generateKeyPair();
        byte[] signature = Curve.calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().getBytes());

        return new SignedPreKeyRecord(signedPreKeyId, System.currentTimeMillis(), keyPair, signature);
    }


    public static ECKeyPair generateSenderSigningKey() throws SodiumException {
        return Curve.generateKeyPair();
    }

    public static byte[] generateSenderKey() {
        try {
            byte[] key = new byte[32];
            SecureRandom.getInstance("SHA1PRNG").nextBytes(key);

            return key;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    public static int generateSenderKeyId() {
        try {
            return SecureRandom.getInstance("SHA1PRNG").nextInt(Integer.MAX_VALUE);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

}
