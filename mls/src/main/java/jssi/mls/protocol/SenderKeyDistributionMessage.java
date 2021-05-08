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
package jssi.mls.protocol;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.InvalidMessageException;
import jssi.mls.LegacyMessageException;
import jssi.mls.protocol.MLSProtos;
import jssi.mls.util.ByteUtil;

public class SenderKeyDistributionMessage implements CiphertextMessage {

    private final int id;
    private final int iteration;
    private final byte[] chainKey;
    private final ECPublicKey signatureKey;
    private final byte[] serialized;

    public SenderKeyDistributionMessage(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
        byte[] version = {ByteUtil.intsToByteHighAndLow(CURRENT_VERSION, CURRENT_VERSION)};
        byte[] protobuf = MLSProtos.SenderKeyDistributionMessage.newBuilder()
                .setId(id)
                .setIteration(iteration)
                .setChainKey(ByteString.copyFrom(chainKey))
                .setSigningKey(ByteString.copyFrom(signatureKey.getBytes()))
                .build().toByteArray();

        this.id = id;
        this.iteration = iteration;
        this.chainKey = chainKey;
        this.signatureKey = signatureKey;
        this.serialized = ByteUtil.concatenate(version, protobuf);
    }

    public SenderKeyDistributionMessage(byte[] serialized) throws LegacyMessageException, InvalidMessageException {
        try {
            byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.length - 1);
            byte version = messageParts[0][0];
            byte[] message = messageParts[1];

            if (ByteUtil.highBitsToInt(version) < CiphertextMessage.CURRENT_VERSION) {
                throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
            }

            if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION) {
                throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
            }

            MLSProtos.SenderKeyDistributionMessage distributionMessage = MLSProtos.SenderKeyDistributionMessage.parseFrom(message);

            if (!distributionMessage.hasId() ||
                    !distributionMessage.hasIteration() ||
                    !distributionMessage.hasChainKey() ||
                    !distributionMessage.hasSigningKey()) {
                throw new InvalidMessageException("Incomplete message.");
            }

            this.serialized = serialized;
            this.id = distributionMessage.getId();
            this.iteration = distributionMessage.getIteration();
            this.chainKey = distributionMessage.getChainKey().toByteArray();
            this.signatureKey = Curve.getECPublicKey(distributionMessage.getSigningKey().toByteArray());
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidMessageException(e);
        }
    }

    @Override
    public byte[] serialize() {
        return serialized;
    }

    @Override
    public int getType() {
        return SENDERKEY_DISTRIBUTION_TYPE;
    }

    public int getIteration() {
        return iteration;
    }

    public byte[] getChainKey() {
        return chainKey;
    }

    public ECPublicKey getSignatureKey() {
        return signatureKey;
    }

    public int getId() {
        return id;
    }
}
