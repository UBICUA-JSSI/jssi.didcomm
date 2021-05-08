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

import com.google.protobuf.ByteString;
import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPrivateKey;
import jssi.mls.ecc.ECPublicKey;

import java.io.IOException;

import static jssi.mls.state.StorageProtos.SignedPreKeyRecordStructure;

public class SignedPreKeyRecord {

    private SignedPreKeyRecordStructure structure;

    public SignedPreKeyRecord(int id, long timestamp, ECKeyPair keyPair, byte[] signature) {
        this.structure = SignedPreKeyRecordStructure.newBuilder()
                .setId(id)
                .setPublicKey(ByteString.copyFrom(keyPair.getPublicKey().getBytes()))
                .setPrivateKey(ByteString.copyFrom(keyPair.getPrivateKey().getBytes()))
                .setSignature(ByteString.copyFrom(signature))
                .setTimestamp(timestamp)
                .build();
    }

    public SignedPreKeyRecord(byte[] serialized) throws IOException {
        this.structure = SignedPreKeyRecordStructure.parseFrom(serialized);
    }

    public int getId() {
        return this.structure.getId();
    }

    public long getTimestamp() {
        return this.structure.getTimestamp();
    }

    public ECKeyPair getKeyPair() {

        ECPublicKey publicKey = Curve.getECPublicKey(this.structure.getPublicKey().toByteArray());
        ECPrivateKey privateKey = Curve.getECPrivateKey(this.structure.getPrivateKey().toByteArray());

        return new ECKeyPair(publicKey, privateKey);
    }

    public byte[] getSignature() {
        return this.structure.getSignature().toByteArray();
    }

    public byte[] serialize() {
        return this.structure.toByteArray();
    }
}
