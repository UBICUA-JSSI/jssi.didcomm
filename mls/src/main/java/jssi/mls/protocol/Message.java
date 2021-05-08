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
import jssi.mls.IdentityKey;
import jssi.mls.InvalidMessageException;
import jssi.mls.LegacyMessageException;
import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.util.ByteUtil;
import jssi.mls.protocol.MLSProtos;
import org.libsodium.api.Crypto_auth_hmacsha256;
import org.libsodium.jni.SodiumException;

import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.text.ParseException;

public class Message implements CiphertextMessage {

    private static final int MAC_LENGTH = 8;

    private final int messageVersion;
    private final ECPublicKey senderRatchetKey;
    private final int counter;
    private final int previousCounter;
    private final byte[] ciphertext;
    private final byte[] serialized;

    public Message(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
        try {
            byte[][] messageParts = ByteUtil.split(serialized, 1, serialized.length - 1 - MAC_LENGTH, MAC_LENGTH);
            byte version = messageParts[0][0];
            byte[] message = messageParts[1];
            byte[] mac = messageParts[2];

            if (ByteUtil.highBitsToInt(version) < CURRENT_VERSION) {
                throw new LegacyMessageException("Legacy message: " + ByteUtil.highBitsToInt(version));
            }

            if (ByteUtil.highBitsToInt(version) > CURRENT_VERSION) {
                throw new InvalidMessageException("Unknown version: " + ByteUtil.highBitsToInt(version));
            }

            MLSProtos.Message whisperMessage = MLSProtos.Message.parseFrom(message);

            if (!whisperMessage.hasCiphertext() ||
                    !whisperMessage.hasCounter() ||
                    !whisperMessage.hasRatchetKey()) {
                throw new InvalidMessageException("Incomplete message.");
            }

            this.serialized = serialized;
            this.senderRatchetKey = Curve.getECPublicKey(whisperMessage.getRatchetKey().toByteArray());
            this.messageVersion = ByteUtil.highBitsToInt(version);
            this.counter = whisperMessage.getCounter();
            this.previousCounter = whisperMessage.getPreviousCounter();
            this.ciphertext = whisperMessage.getCiphertext().toByteArray();
        } catch (InvalidProtocolBufferException | ParseException e) {
            throw new InvalidMessageException(e);
        }
    }

    public Message(int messageVersion, SecretKeySpec macKey, ECPublicKey senderRatchetKey,
                   int counter, int previousCounter, byte[] ciphertext,
                   IdentityKey senderIdentityKey,
                   IdentityKey receiverIdentityKey) {
        byte[] version = {ByteUtil.intsToByteHighAndLow(messageVersion, CURRENT_VERSION)};
        byte[] message = MLSProtos.Message.newBuilder()
                .setRatchetKey(ByteString.copyFrom(senderRatchetKey.getBytes()))
                .setCounter(counter)
                .setPreviousCounter(previousCounter)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .build().toByteArray();

        byte[] mac = getMac(senderIdentityKey, receiverIdentityKey, macKey, ByteUtil.concatenate(version, message));

        this.serialized = ByteUtil.concatenate(version, message, mac);
        this.senderRatchetKey = senderRatchetKey;
        this.counter = counter;
        this.previousCounter = previousCounter;
        this.ciphertext = ciphertext;
        this.messageVersion = messageVersion;
    }

    public ECPublicKey getSenderRatchetKey() {
        return senderRatchetKey;
    }

    public int getMessageVersion() {
        return messageVersion;
    }

    public int getCounter() {
        return counter;
    }

    public byte[] getBody() {
        return ciphertext;
    }

    public void verifyMac(IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey)
            throws InvalidMessageException {
        byte[][] parts = ByteUtil.split(serialized, serialized.length - MAC_LENGTH, MAC_LENGTH);
        byte[] ourMac = getMac(senderIdentityKey, receiverIdentityKey, macKey, parts[0]);
        byte[] theirMac = parts[1];

        if (!MessageDigest.isEqual(ourMac, theirMac)) {
            throw new InvalidMessageException("Bad Mac!");
        }
    }

    private byte[] getMac(IdentityKey senderIdentityKey,
                          IdentityKey receiverIdentityKey,
                          SecretKeySpec macKey, byte[] serialized) {
        try {
            byte[] state = Crypto_auth_hmacsha256.init(macKey.getEncoded());
            state = Crypto_auth_hmacsha256.update(state, senderIdentityKey.getPublicKey().getBytes());
            state = Crypto_auth_hmacsha256.update(state, receiverIdentityKey.getPublicKey().getBytes());
            state = Crypto_auth_hmacsha256.update(state, serialized);
            byte[] fullMac = Crypto_auth_hmacsha256.finalize(state);

            return ByteUtil.trim(fullMac, MAC_LENGTH);
        } catch (SodiumException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public byte[] serialize() {
        return serialized;
    }

    @Override
    public int getType() {
        return CiphertextMessage.WHISPER_TYPE;
    }

    public static boolean isLegacy(byte[] message) {
        return message != null && message.length >= 1 &&
                ByteUtil.highBitsToInt(message[0]) != CiphertextMessage.CURRENT_VERSION;
    }

}
