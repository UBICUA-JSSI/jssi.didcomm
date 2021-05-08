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

public class FingerprintIdentifierMismatchException extends Exception {

    private final String localIdentifier;
    private final String remoteIdentifier;
    private final String scannedLocalIdentifier;
    private final String scannedRemoteIdentifier;

    public FingerprintIdentifierMismatchException(String localIdentifier, String remoteIdentifier,
                                                  String scannedLocalIdentifier, String scannedRemoteIdentifier) {
        this.localIdentifier = localIdentifier;
        this.remoteIdentifier = remoteIdentifier;
        this.scannedLocalIdentifier = scannedLocalIdentifier;
        this.scannedRemoteIdentifier = scannedRemoteIdentifier;
    }

    public String getScannedRemoteIdentifier() {
        return scannedRemoteIdentifier;
    }

    public String getScannedLocalIdentifier() {
        return scannedLocalIdentifier;
    }

    public String getRemoteIdentifier() {
        return remoteIdentifier;
    }

    public String getLocalIdentifier() {
        return localIdentifier;
    }
}
