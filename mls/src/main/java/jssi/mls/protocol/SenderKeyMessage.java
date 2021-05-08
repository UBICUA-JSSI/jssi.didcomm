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
import jssi.mls.ecc.ECPrivateKey;
import jssi.mls.ecc.ECPublicKey;
import org.libsodium.jni.SodiumException;
import jssi.mls.InvalidKeyException;
import jssi.mls.InvalidMessageException;
import jssi.mls.LegacyMessageException;
import jssi.mls.protocol.MLSProtos;
import jssi.mls.util.ByteUtil;

import java.text.ParseException;

public class SenderKeyMessage implements CiphertextMessage {

    private static final int SIGNATURE_LENGTH = 64;

    private final int messageVersion;
    private final int keyId;
    private final int iteration;
    private final byte[] ciphertext;
    private final byte[] serialized;

    public SenderKeyMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
        try {
            byte[][] messageParts = ByteUtil.split(serialized,
                    1,
                    (serialized.length - 2 - SIGNATURE_LENGTH) / 2,
                    (serialized.length + SIGNATURE_LENGTH) / 2);

            byte version = messageParts[0][0];
            byte[] message = messageParts[1];
            byte[] signature = messageParts[2];

            if (ByteUtil.highBitsToInt(version) < 3) {
                throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
            }

            if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION) {
                throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
            }

            MLSProtos.SenderKeyMessage senderKeyMessage = MLSProtos.SenderKeyMessage.parseFrom(message);

            if (!senderKeyMessage.hasId() ||
                    !senderKeyMessage.hasIteration() ||
                    !senderKeyMessage.hasCiphertext()) {
                throw new InvalidMessageException("Incomplete message.");
            }

            this.serialized = serialized;
            this.messageVersion = ByteUtil.highBitsToInt(version);
            this.keyId = senderKeyMessage.getId();
            this.iteration = senderKeyMessage.getIteration();
            this.ciphertext = senderKeyMessage.getCiphertext().toByteArray();
        } catch (InvalidProtocolBufferException | ParseException e) {
            throw new InvalidMessageException(e);
        }
    }

    public SenderKeyMessage(int keyId, int iteration, byte[] ciphertext, ECPrivateKey signatureKey) {
        byte[] version = {ByteUtil.intsToByteHighAndLow(CURRENT_VERSION, CURRENT_VERSION)};
        byte[] message = MLSProtos.SenderKeyMessage.newBuilder()
                .setId(keyId)
                .setIteration(iteration)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .build().toByteArray();

        byte[] signature = getSignature(signatureKey, ByteUtil.concatenate(version, message));

        this.serialized = ByteUtil.concatenate(version, message, signature);
        this.messageVersion = CURRENT_VERSION;
        this.keyId = keyId;
        this.iteration = iteration;
        this.ciphertext = ciphertext;
    }

    public int getKeyId() {
        return keyId;
    }

    public int getIteration() {
        return iteration;
    }

    public byte[] getCipherText() {
        return ciphertext;
    }

    public void verifySignature(ECPublicKey signatureKey)
            throws InvalidMessageException {
        try {
            byte[][] parts = ByteUtil.split(serialized,
                    1,
                    (serialized.length - 2 - SIGNATURE_LENGTH) / 2,
                    (serialized.length + SIGNATURE_LENGTH) / 2);

            if (!Curve.verifySignature(signatureKey, parts[1], parts[2])) {
                throw new InvalidMessageException("Invalid signature!");
            }

        } catch (InvalidKeyException | SodiumException | ParseException e) {
            throw new InvalidMessageException(e);
        }
    }

    private byte[] getSignature(ECPrivateKey signatureKey, byte[] serialized) {
        try {
            return Curve.calculateSignature(signatureKey, serialized);
        } catch (InvalidKeyException | SodiumException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public byte[] serialize() {
        return serialized;
    }

    @Override
    public int getType() {
        return CiphertextMessage.SENDERKEY_TYPE;
    }
}
