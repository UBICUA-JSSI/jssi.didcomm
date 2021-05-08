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
package jssi.mls.state;

import jssi.mls.ecc.ECPublicKey;
import jssi.mls.IdentityKey;

/**
 * A class that contains a remote PreKey and collection
 * of associated items.
 *
 * @author Moxie Marlinspike
 */
public class PreKeyBundle {

    private final int registrationId;
    private final int deviceId;
    private final int preKeyId;
    private final ECPublicKey preKeyPublic;
    private final int signedPreKeyId;
    private final ECPublicKey signedPreKeyPublic;
    private final byte[] signedPreKeySignature;
    private final IdentityKey identityKey;

    public PreKeyBundle(int registrationId, int deviceId, int preKeyId, ECPublicKey preKeyPublic,
                        int signedPreKeyId, ECPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                        IdentityKey identityKey) {
        this.registrationId = registrationId;
        this.deviceId = deviceId;
        this.preKeyId = preKeyId;
        this.preKeyPublic = preKeyPublic;
        this.signedPreKeyId = signedPreKeyId;
        this.signedPreKeyPublic = signedPreKeyPublic;
        this.signedPreKeySignature = signedPreKeySignature;
        this.identityKey = identityKey;
    }

    /**
     * @return the device ID this PreKey belongs to.
     */
    public int getDeviceId() {
        return deviceId;
    }

    /**
     * @return the unique key ID for this PreKey.
     */
    public int getPreKeyId() {
        return preKeyId;
    }

    /**
     * @return the public key for this PreKey.
     */
    public ECPublicKey getPreKey() {
        return preKeyPublic;
    }

    /**
     * @return the unique key ID for this signed prekey.
     */
    public int getSignedPreKeyId() {
        return signedPreKeyId;
    }

    /**
     * @return the signed prekey for this PreKeyBundle.
     */
    public ECPublicKey getSignedPreKey() {
        return signedPreKeyPublic;
    }

    /**
     * @return the signature over the signed  prekey.
     */
    public byte[] getSignedPreKeySignature() {
        return signedPreKeySignature;
    }

    /**
     * @return the {@link IdentityKey} of this PreKeys owner.
     */
    public IdentityKey getIdentityKey() {
        return identityKey;
    }

    /**
     * @return the registration ID associated with this PreKey.
     */
    public int getRegistrationId() {
        return registrationId;
    }
}
