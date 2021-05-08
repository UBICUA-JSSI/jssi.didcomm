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
package jssi.mls.groups.state;

import com.google.protobuf.ByteString;

import jssi.mls.InvalidKeyException;
import jssi.mls.ecc.*;
import jssi.mls.groups.ratchet.SenderChainKey;
import jssi.mls.groups.ratchet.SenderMessageKey;
import jssi.mls.util.guava.Optional;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import static jssi.mls.state.StorageProtos.SenderKeyStateStructure;

/**
 * Represents the state of an individual SenderKey ratchet.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyState {

    private static final int MAX_MESSAGE_KEYS = 2000;

    private SenderKeyStateStructure senderKeyStateStructure;

    public SenderKeyState(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
        this(id, iteration, chainKey, signatureKey, Optional.<ECPrivateKey>absent());
    }

    public SenderKeyState(int id, int iteration, byte[] chainKey, ECKeyPair signatureKey) {
        this(id, iteration, chainKey, signatureKey.getPublicKey(), Optional.of(signatureKey.getPrivateKey()));
    }

    private SenderKeyState(int id, int iteration, byte[] chainKey,
                           ECPublicKey signatureKeyPublic,
                           Optional<ECPrivateKey> signatureKeyPrivate) {
        SenderKeyStateStructure.SenderChainKey senderChainKeyStructure =
                SenderKeyStateStructure.SenderChainKey.newBuilder()
                        .setIteration(iteration)
                        .setSeed(ByteString.copyFrom(chainKey))
                        .build();

        SenderKeyStateStructure.SenderSigningKey.Builder signingKeyStructure =
                SenderKeyStateStructure.SenderSigningKey.newBuilder()
                        .setPublic(ByteString.copyFrom(signatureKeyPublic.getBytes()));

        if (signatureKeyPrivate.isPresent()) {
            signingKeyStructure.setPrivate(ByteString.copyFrom(signatureKeyPrivate.get().getBytes()));
        }

        this.senderKeyStateStructure = SenderKeyStateStructure.newBuilder()
                .setSenderKeyId(id)
                .setSenderChainKey(senderChainKeyStructure)
                .setSenderSigningKey(signingKeyStructure)
                .build();
    }

    public SenderKeyState(SenderKeyStateStructure senderKeyStateStructure) {
        this.senderKeyStateStructure = senderKeyStateStructure;
    }

    public int getKeyId() {
        return senderKeyStateStructure.getSenderKeyId();
    }

    public SenderChainKey getSenderChainKey() {
        return new SenderChainKey(senderKeyStateStructure.getSenderChainKey().getIteration(),
                senderKeyStateStructure.getSenderChainKey().getSeed().toByteArray());
    }

    public void setSenderChainKey(SenderChainKey chainKey) {
        SenderKeyStateStructure.SenderChainKey senderChainKeyStructure =
                SenderKeyStateStructure.SenderChainKey.newBuilder()
                        .setIteration(chainKey.getIteration())
                        .setSeed(ByteString.copyFrom(chainKey.getSeed()))
                        .build();

        this.senderKeyStateStructure = senderKeyStateStructure.toBuilder()
                .setSenderChainKey(senderChainKeyStructure)
                .build();
    }

    public ECPublicKey getSigningKeyPublic() throws InvalidKeyException {
        return new EDPublicKey(senderKeyStateStructure.getSenderSigningKey()
                .getPublic().toByteArray());
    }

    public ECPrivateKey getSigningKeyPrivate() {
        return new EDPrivateKey(senderKeyStateStructure.getSenderSigningKey()
                .getPrivate().toByteArray());
    }

    public boolean hasSenderMessageKey(int iteration) {
        for (SenderKeyStateStructure.SenderMessageKey senderMessageKey : senderKeyStateStructure.getSenderMessageKeysList()) {
            if (senderMessageKey.getIteration() == iteration) return true;
        }

        return false;
    }

    public void addSenderMessageKey(SenderMessageKey senderMessageKey) {
        SenderKeyStateStructure.SenderMessageKey senderMessageKeyStructure =
                SenderKeyStateStructure.SenderMessageKey.newBuilder()
                        .setIteration(senderMessageKey.getIteration())
                        .setSeed(ByteString.copyFrom(senderMessageKey.getSeed()))
                        .build();

        SenderKeyStateStructure.Builder builder = this.senderKeyStateStructure.toBuilder();

        builder.addSenderMessageKeys(senderMessageKeyStructure);

        if (builder.getSenderMessageKeysCount() > MAX_MESSAGE_KEYS) {
            builder.removeSenderMessageKeys(0);
        }

        this.senderKeyStateStructure = builder.build();
    }

    public SenderMessageKey removeSenderMessageKey(int iteration) {
        List<SenderKeyStateStructure.SenderMessageKey> keys = new LinkedList<>(senderKeyStateStructure.getSenderMessageKeysList());
        Iterator<SenderKeyStateStructure.SenderMessageKey> iterator = keys.iterator();

        SenderKeyStateStructure.SenderMessageKey result = null;

        while (iterator.hasNext()) {
            SenderKeyStateStructure.SenderMessageKey senderMessageKey = iterator.next();

            if (senderMessageKey.getIteration() == iteration) {
                result = senderMessageKey;
                iterator.remove();
                break;
            }
        }

        this.senderKeyStateStructure = this.senderKeyStateStructure.toBuilder()
                .clearSenderMessageKeys()
                .addAllSenderMessageKeys(keys)
                .build();

        if (result != null) {
            return new SenderMessageKey(result.getIteration(), result.getSeed().toByteArray());
        } else {
            return null;
        }
    }

    public SenderKeyStateStructure getStructure() {
        return senderKeyStateStructure;
    }
}
