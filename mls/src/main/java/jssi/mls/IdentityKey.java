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
package jssi.mls;


import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.util.Hex;

/**
 * A class for representing an identity key.
 *
 * @author Moxie Marlinspike
 */

public class IdentityKey {

    private final ECPublicKey publicKey;

    public IdentityKey(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public IdentityKey(byte[] bytes) throws InvalidKeyException {
        this.publicKey = Curve.getECPublicKey(bytes);
    }

    public ECPublicKey getPublicKey() {
        return publicKey;
    }

    public byte[] getBytes() {
        return publicKey.getBytes();
    }

    public String getFingerprint() {
        return Hex.toString(publicKey.getBytes());
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) return false;
        if (!(other instanceof IdentityKey)) return false;

        return publicKey.equals(((IdentityKey) other).getPublicKey());
    }

    @Override
    public int hashCode() {
        return publicKey.hashCode();
    }
}
