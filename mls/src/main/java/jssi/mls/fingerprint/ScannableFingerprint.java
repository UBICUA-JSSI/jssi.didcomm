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

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import jssi.mls.fingerprint.FingerprintProtos.CombinedFingerprints;
import jssi.mls.fingerprint.FingerprintProtos.LogicalFingerprint;
import jssi.mls.util.ByteUtil;

import java.security.MessageDigest;

public class ScannableFingerprint {

    private final int version;
    private final CombinedFingerprints fingerprints;

    ScannableFingerprint(int version, byte[] localFingerprintData, byte[] remoteFingerprintData) {
        LogicalFingerprint localFingerprint = LogicalFingerprint.newBuilder()
                .setContent(ByteString.copyFrom(ByteUtil.trim(localFingerprintData, 32)))
                .build();

        LogicalFingerprint remoteFingerprint = LogicalFingerprint.newBuilder()
                .setContent(ByteString.copyFrom(ByteUtil.trim(remoteFingerprintData, 32)))
                .build();

        this.version = version;
        this.fingerprints = CombinedFingerprints.newBuilder()
                .setVersion(version)
                .setLocalFingerprint(localFingerprint)
                .setRemoteFingerprint(remoteFingerprint)
                .build();
    }

    /**
     * @return A byte string to be displayed in a QR code.
     */
    public byte[] getSerialized() {
        return fingerprints.toByteArray();
    }

    /**
     * Compare a scanned QR code with what we expect.
     *
     * @param scannedFingerprintData The scanned data
     * @return True if matching, otherwise false.
     * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
     */
    public boolean compareTo(byte[] scannedFingerprintData)
            throws FingerprintVersionMismatchException,
            FingerprintParsingException {
        try {
            CombinedFingerprints scanned = CombinedFingerprints.parseFrom(scannedFingerprintData);

            if (!scanned.hasRemoteFingerprint() || !scanned.hasLocalFingerprint() ||
                    !scanned.hasVersion() || scanned.getVersion() != version) {
                throw new FingerprintVersionMismatchException(scanned.getVersion(), version);
            }

            return MessageDigest.isEqual(fingerprints.getLocalFingerprint().getContent().toByteArray(), scanned.getRemoteFingerprint().getContent().toByteArray()) &&
                    MessageDigest.isEqual(fingerprints.getRemoteFingerprint().getContent().toByteArray(), scanned.getLocalFingerprint().getContent().toByteArray());
        } catch (InvalidProtocolBufferException e) {
            throw new FingerprintParsingException(e);
        }
    }
}
