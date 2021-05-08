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
package jssi.mls.fingerprint;

import jssi.mls.IdentityKey;
import jssi.mls.util.ByteUtil;
import jssi.mls.util.IdentityKeyComparator;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class NumericFingerprintGenerator implements FingerprintGenerator {

    private static final int FINGERPRINT_VERSION = 0;

    private final int iterations;

    /**
     * Construct a fingerprint generator for 60 digit numerics.
     *
     * @param iterations The number of internal iterations to perform in the process of
     *                   generating a fingerprint. This needs to be constant, and synchronized
     *                   across all clients.
     *
     *                   The higher the iteration count, the higher the security level:
     *
     *                   - 1024 ~ 109.7 bits
     *                   - 1400 > 110 bits
     *                   - 5200 > 112 bits
     */
    public NumericFingerprintGenerator(int iterations) {
        this.iterations = iterations;
    }

    /**
     * Generate a scannable and displayable fingerprint.
     *
     * @param version The version of fingerprint you are generating.
     * @param localStableIdentifier The client's "stable" identifier.
     * @param localIdentityKey The client's identity key.
     * @param remoteStableIdentifier The remote party's "stable" identifier.
     * @param remoteIdentityKey The remote party's identity key.
     * @return A unique fingerprint for this conversation.
     */
    @Override
    public Fingerprint createFor(int version,
                                 byte[] localStableIdentifier,
                                 final IdentityKey localIdentityKey,
                                 byte[] remoteStableIdentifier,
                                 final IdentityKey remoteIdentityKey) {
        return createFor(version,
                localStableIdentifier,
                new LinkedList<>() {{
                    add(localIdentityKey);
                }},
                remoteStableIdentifier,
                new LinkedList<>() {{
                    add(remoteIdentityKey);
                }});
    }

    /**
     * Generate a scannable and displayable fingerprint for logical identities that have multiple
     * physical keys.
     *
     * Do not trust the output of this unless you've been through the device consistency process
     * for the provided localIdentityKeys.
     *
     * @param version The version of fingerprint you are generating.
     * @param localStableIdentifier The client's "stable" identifier.
     * @param localIdentityKeys The client's collection of physical identity keys.
     * @param remoteStableIdentifier The remote party's "stable" identifier.
     * @param remoteIdentityKeys The remote party's collection of physical identity key.
     * @return A unique fingerprint for this conversation.
     */
    public Fingerprint createFor(int version,
                                 byte[] localStableIdentifier,
                                 List<IdentityKey> localIdentityKeys,
                                 byte[] remoteStableIdentifier,
                                 List<IdentityKey> remoteIdentityKeys) {
        byte[] localFingerprint = getFingerprint(iterations, localStableIdentifier, localIdentityKeys);
        byte[] remoteFingerprint = getFingerprint(iterations, remoteStableIdentifier, remoteIdentityKeys);

        DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(localFingerprint, remoteFingerprint);
        ScannableFingerprint scannableFingerprint = new ScannableFingerprint(version, localFingerprint, remoteFingerprint);

        return new Fingerprint(displayableFingerprint, scannableFingerprint);
    }

    private byte[] getFingerprint(int iterations, byte[] stableIdentifier, List<IdentityKey> unsortedIdentityKeys) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] publicKey = getLogicalKeyBytes(unsortedIdentityKeys);
            byte[] hash = ByteUtil.concatenate(ByteUtil.shortToByteArray(FINGERPRINT_VERSION), publicKey, stableIdentifier);

            for (int i = 0; i < iterations; i++) {
                digest.update(hash);
                hash = digest.digest(publicKey);
            }

            return hash;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private byte[] getLogicalKeyBytes(List<IdentityKey> identityKeys) {
        ArrayList<IdentityKey> sortedIdentityKeys = new ArrayList<>(identityKeys);
        sortedIdentityKeys.sort(new IdentityKeyComparator());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        for (IdentityKey identityKey : sortedIdentityKeys) {
            byte[] publicKeyBytes = identityKey.getPublicKey().getBytes();
            baos.write(publicKeyBytes, 0, publicKeyBytes.length);
        }

        return baos.toByteArray();
    }
}
