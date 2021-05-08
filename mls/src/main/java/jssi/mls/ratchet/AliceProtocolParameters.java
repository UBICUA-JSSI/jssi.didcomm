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

import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.IdentityKey;
import jssi.mls.IdentityKeyPair;
import jssi.mls.util.guava.Optional;

public class AliceProtocolParameters {

    private final IdentityKeyPair ourIdentityKey;
    private final ECKeyPair ourBaseKey;

    private final IdentityKey theirIdentityKey;
    private final ECPublicKey theirSignedPreKey;
    private final Optional<ECPublicKey> theirOneTimePreKey;
    private final ECPublicKey theirRatchetKey;

    private AliceProtocolParameters(IdentityKeyPair ourIdentityKey, ECKeyPair ourBaseKey,
                                    IdentityKey theirIdentityKey, ECPublicKey theirSignedPreKey,
                                    ECPublicKey theirRatchetKey, Optional<ECPublicKey> theirOneTimePreKey) {
        this.ourIdentityKey = ourIdentityKey;
        this.ourBaseKey = ourBaseKey;
        this.theirIdentityKey = theirIdentityKey;
        this.theirSignedPreKey = theirSignedPreKey;
        this.theirRatchetKey = theirRatchetKey;
        this.theirOneTimePreKey = theirOneTimePreKey;

        if (ourIdentityKey == null || ourBaseKey == null || theirIdentityKey == null ||
                theirSignedPreKey == null || theirRatchetKey == null || theirOneTimePreKey == null) {
            throw new IllegalArgumentException("Null values!");
        }
    }

    public IdentityKeyPair getOurIdentityKey() {
        return ourIdentityKey;
    }

    public ECKeyPair getOurBaseKey() {
        return ourBaseKey;
    }

    public IdentityKey getTheirIdentityKey() {
        return theirIdentityKey;
    }

    public ECPublicKey getTheirSignedPreKey() {
        return theirSignedPreKey;
    }

    public Optional<ECPublicKey> getTheirOneTimePreKey() {
        return theirOneTimePreKey;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public ECPublicKey getTheirRatchetKey() {
        return theirRatchetKey;
    }

    public static class Builder {
        private IdentityKeyPair ourIdentityKey;
        private ECKeyPair ourBaseKey;

        private IdentityKey theirIdentityKey;
        private ECPublicKey theirSignedPreKey;
        private ECPublicKey theirRatchetKey;
        private Optional<ECPublicKey> theirOneTimePreKey;

        public Builder setOurIdentityKey(IdentityKeyPair ourIdentityKey) {
            this.ourIdentityKey = ourIdentityKey;
            return this;
        }

        public Builder setOurBaseKey(ECKeyPair ourBaseKey) {
            this.ourBaseKey = ourBaseKey;
            return this;
        }

        public Builder setTheirRatchetKey(ECPublicKey theirRatchetKey) {
            this.theirRatchetKey = theirRatchetKey;
            return this;
        }

        public Builder setTheirIdentityKey(IdentityKey theirIdentityKey) {
            this.theirIdentityKey = theirIdentityKey;
            return this;
        }

        public Builder setTheirSignedPreKey(ECPublicKey theirSignedPreKey) {
            this.theirSignedPreKey = theirSignedPreKey;
            return this;
        }

        public Builder setTheirOneTimePreKey(Optional<ECPublicKey> theirOneTimePreKey) {
            this.theirOneTimePreKey = theirOneTimePreKey;
            return this;
        }

        public AliceProtocolParameters create() {
            return new AliceProtocolParameters(ourIdentityKey, ourBaseKey, theirIdentityKey,
                    theirSignedPreKey, theirRatchetKey, theirOneTimePreKey);
        }
    }
}
