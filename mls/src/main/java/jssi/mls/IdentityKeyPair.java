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

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECPrivateKey;

import static jssi.mls.state.StorageProtos.IdentityKeyPairStructure;

/**
 * Holder for public and private identity key pair.
 *
 * @author Moxie Marlinspike
 */
public class IdentityKeyPair {

    private final IdentityKey publicKey;
    private final ECPrivateKey privateKey;

    public IdentityKeyPair(IdentityKey publicKey, ECPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public IdentityKeyPair(byte[] serialized) throws InvalidKeyException {
        try {
            IdentityKeyPairStructure structure = IdentityKeyPairStructure.parseFrom(serialized);
            this.publicKey = new IdentityKey(structure.getPublicKey().toByteArray());
            this.privateKey = Curve.getECPrivateKey(structure.getPrivateKey().toByteArray());
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidKeyException(e);
        }
    }

    public IdentityKey getPublicKey() {
        return publicKey;
    }

    public ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    public byte[] serialize() {
        return IdentityKeyPairStructure.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getBytes()))
                .setPrivateKey(ByteString.copyFrom(privateKey.getBytes()))
                .build().toByteArray();
    }
}
