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

import jssi.mls.util.ByteUtil;

public class DisplayableFingerprint {

    private final String localFingerprintNumbers;
    private final String remoteFingerprintNumbers;

    DisplayableFingerprint(byte[] localFingerprint, byte[] remoteFingerprint) {
        this.localFingerprintNumbers = getDisplayStringFor(localFingerprint);
        this.remoteFingerprintNumbers = getDisplayStringFor(remoteFingerprint);
    }

    public String getDisplayText() {
        if (localFingerprintNumbers.compareTo(remoteFingerprintNumbers) <= 0) {
            return localFingerprintNumbers + remoteFingerprintNumbers;
        } else {
            return remoteFingerprintNumbers + localFingerprintNumbers;
        }
    }

    private String getDisplayStringFor(byte[] fingerprint) {
        return getEncodedChunk(fingerprint, 0) +
                getEncodedChunk(fingerprint, 5) +
                getEncodedChunk(fingerprint, 10) +
                getEncodedChunk(fingerprint, 15) +
                getEncodedChunk(fingerprint, 20) +
                getEncodedChunk(fingerprint, 25);
    }

    private String getEncodedChunk(byte[] hash, int offset) {
        long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
        return String.format("%05d", chunk);
    }

}
