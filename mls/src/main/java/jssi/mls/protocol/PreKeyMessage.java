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
import jssi.mls.IdentityKey;
import jssi.mls.InvalidMessageException;
import jssi.mls.InvalidVersionException;
import jssi.mls.LegacyMessageException;
import jssi.mls.protocol.MLSProtos;
import jssi.mls.util.ByteUtil;
import jssi.mls.util.guava.Optional;

public class PreKeyMessage implements CiphertextMessage {

    private final int version;
    private final int registrationId;
    private final Optional<Integer> preKeyId;
    private final int signedPreKeyId;
    private final ECPublicKey baseKey;
    private final IdentityKey identityKey;
    private final Message message;
    private final byte[] serialized;

    public PreKeyMessage(byte[] serialized)
            throws InvalidMessageException, InvalidVersionException {
        try {
            this.version = ByteUtil.highBitsToInt(serialized[0]);

            if (this.version > CiphertextMessage.CURRENT_VERSION) {
                throw new InvalidVersionException("Unknown version: " + this.version);
            }

            if (this.version < CiphertextMessage.CURRENT_VERSION) {
                throw new LegacyMessageException("Legacy version: " + this.version);
            }

            MLSProtos.PreKeyMessage preKeyWhisperMessage
                    = MLSProtos.PreKeyMessage.parseFrom(ByteString.copyFrom(serialized, 1,
                    serialized.length - 1));

            if (!preKeyWhisperMessage.hasSignedPreKeyId() ||
                    !preKeyWhisperMessage.hasBaseKey() ||
                    !preKeyWhisperMessage.hasIdentityKey() ||
                    !preKeyWhisperMessage.hasMessage()) {
                throw new InvalidMessageException("Incomplete message.");
            }

            this.serialized = serialized;
            this.registrationId = preKeyWhisperMessage.getRegistrationId();
            this.preKeyId = preKeyWhisperMessage.hasPreKeyId() ? Optional.of(preKeyWhisperMessage.getPreKeyId()) : Optional.absent();
            this.signedPreKeyId = preKeyWhisperMessage.hasSignedPreKeyId() ? preKeyWhisperMessage.getSignedPreKeyId() : -1;
            this.baseKey = Curve.getECPublicKey(preKeyWhisperMessage.getBaseKey().toByteArray());
            this.identityKey = new IdentityKey(Curve.getECPublicKey(preKeyWhisperMessage.getIdentityKey().toByteArray()));
            this.message = new Message(preKeyWhisperMessage.getMessage().toByteArray());
        } catch (InvalidProtocolBufferException | LegacyMessageException e) {
            throw new InvalidMessageException(e);
        }
    }

    public PreKeyMessage(int messageVersion, int registrationId, Optional<Integer> preKeyId,
                         int signedPreKeyId, ECPublicKey baseKey, IdentityKey identityKey,
                         Message message) {
        this.version = messageVersion;
        this.registrationId = registrationId;
        this.preKeyId = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
        this.baseKey = baseKey;
        this.identityKey = identityKey;
        this.message = message;

        MLSProtos.PreKeyMessage.Builder builder =
                MLSProtos.PreKeyMessage.newBuilder()
                        .setSignedPreKeyId(signedPreKeyId)
                        .setBaseKey(ByteString.copyFrom(baseKey.getBytes()))
                        .setIdentityKey(ByteString.copyFrom(identityKey.getBytes()))
                        .setMessage(ByteString.copyFrom(message.serialize()))
                        .setRegistrationId(registrationId);

        if (preKeyId.isPresent()) {
            builder.setPreKeyId(preKeyId.get());
        }

        byte[] versionBytes = {ByteUtil.intsToByteHighAndLow(this.version, CURRENT_VERSION)};
        byte[] messageBytes = builder.build().toByteArray();

        this.serialized = ByteUtil.concatenate(versionBytes, messageBytes);
    }

    public int getMessageVersion() {
        return version;
    }

    public IdentityKey getIdentityKey() {
        return identityKey;
    }

    public int getRegistrationId() {
        return registrationId;
    }

    public Optional<Integer> getPreKeyId() {
        return preKeyId;
    }

    public int getSignedPreKeyId() {
        return signedPreKeyId;
    }

    public ECPublicKey getBaseKey() {
        return baseKey;
    }

    public Message getWhisperMessage() {
        return message;
    }

    @Override
    public byte[] serialize() {
        return serialized;
    }

    @Override
    public int getType() {
        return CiphertextMessage.PREKEY_TYPE;
    }

}
