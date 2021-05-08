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
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.protocol.CiphertextMessage;
import jssi.mls.protocol.Message;
import jssi.mls.protocol.PreKeyMessage;
import jssi.mls.state.*;
import jssi.mls.util.Pair;
import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SessionBuilderTest {

    public SessionBuilderTest(){
        NaCl.sodium();
    }

    private static final ProtocolAddress ALICE_DID = new ProtocolAddress("8EbSkWapRpCAoGepayMY7y", 1);
    private static final ProtocolAddress BOB_DID = new ProtocolAddress("KHegADqTR3HZFJUS2nHDzD", 1);

    @Test
    public void notSignedPreKey_test() throws UntrustedIdentityException, SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);

        ProtocolStore bobStore = new SSIProtocolStore();
        ECKeyPair bobPreKeyPair = Curve.generateKeyPair();

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                0, null, null,
                bobStore.getIdentityKeyPair().getPublicKey());

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new AssertionError("Should fail with missing unsigned prekey!");
        } catch (InvalidKeyException | SodiumException e) {
            // Good!
            return;
        }
    }

    @Test
    public void signedPreKey_test()
            throws InvalidKeyException,
            InvalidVersionException,
            InvalidMessageException,
            InvalidKeyIdException,
            DuplicateMessageException,
            LegacyMessageException,
            UntrustedIdentityException,
            NoSessionException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);

        final ProtocolStore bobStore = new SSIProtocolStore();
        ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
        byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().getBytes());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(),
                1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(),
                bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        aliceSessionBuilder.process(bobPreKey);

        assertTrue(aliceStore.containsSession(BOB_DID));
        assertTrue(aliceStore.loadSession(BOB_DID).getSessionState().getSessionVersion() == 3);

        final String originalMessage = "L'homme est condamné à être libre";

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

        PreKeyMessage incomingMessage = new PreKeyMessage(outgoingMessage.serialize());
        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);
        byte[] plaintext = bobSessionCipher.decrypt(incomingMessage, new DecryptionCallback() {
            @Override
            public void handlePlaintext(byte[] plaintext) {
                assertTrue(originalMessage.equals(new String(plaintext)));
                assertFalse(bobStore.containsSession(ALICE_DID));
            }
        });

        assertTrue(bobStore.containsSession(ALICE_DID));
        assertTrue(bobStore.loadSession(ALICE_DID).getSessionState().getSessionVersion() == 3);
        assertTrue(bobStore.loadSession(ALICE_DID).getSessionState().getAliceBaseKey() != null);
        assertTrue(originalMessage.equals(new String(plaintext)));

        CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
        assertTrue(bobOutgoingMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new Message(bobOutgoingMessage.serialize()));
        assertTrue(new String(alicePlaintext).equals(originalMessage));

        runInteraction(aliceStore, bobStore);

        aliceStore = new SSIProtocolStore();
        aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);
        aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);

        bobPreKeyPair = Curve.generateKeyPair();
        bobSignedPreKeyPair = Curve.generateKeyPair();
        bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(), bobSignedPreKeyPair.getPublicKey().getBytes());
        bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(),
                1, 31338, bobPreKeyPair.getPublicKey(),
                23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storePreKey(31338, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(23, new SignedPreKeyRecord(23, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));
        aliceSessionBuilder.process(bobPreKey);

        outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        try {
            plaintext = bobSessionCipher.decrypt(new PreKeyMessage(outgoingMessage.serialize()));
            throw new AssertionError("shouldn't be trusted!");
        } catch (UntrustedIdentityException uie) {
            bobStore.saveIdentity(ALICE_DID, new PreKeyMessage(outgoingMessage.serialize()).getIdentityKey());
        }

        plaintext = bobSessionCipher.decrypt(new PreKeyMessage(outgoingMessage.serialize()));
        assertTrue(new String(plaintext).equals(originalMessage));

        bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, Curve.generateKeyPair().getPublicKey(),
                23, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                aliceStore.getIdentityKeyPair().getPublicKey());

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new AssertionError("shoulnd't be trusted!");
        } catch (UntrustedIdentityException uie) {
            // good
        }
    }

    @Test
    public void testBadSignedPreKeySignature() throws InvalidKeyException, UntrustedIdentityException, SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);

        IdentityKeyStore bobIdentityKeyStore = new SSIIdentityKeyStore();

        ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
        byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobIdentityKeyStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().getBytes());


        for (int i = 0; i < bobSignedPreKeySignature.length * 8; i++) {
            byte[] modifiedSignature = new byte[bobSignedPreKeySignature.length];
            System.arraycopy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.length);

            modifiedSignature[i / 8] ^= (0x01 << (i % 8));

            PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.getLocalRegistrationId(), 1,
                    31337, bobPreKeyPair.getPublicKey(),
                    22, bobSignedPreKeyPair.getPublicKey(), modifiedSignature,
                    bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

            try {
                aliceSessionBuilder.process(bobPreKey);
                throw new AssertionError("Accepted modified device key signature!");
            } catch (InvalidKeyException | SodiumException ike) {
                // good
            }
        }

        PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                bobIdentityKeyStore.getIdentityKeyPair().getPublicKey());

        aliceSessionBuilder.process(bobPreKey);
    }

    @Test
    public void notSignedBundleMessage_test() throws InvalidKeyException, UntrustedIdentityException, SodiumException {
        ProtocolStore aliceStore = new SSIProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);

        ProtocolStore bobStore = new SSIProtocolStore();

        ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
        byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().getBytes());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                0, null, null,
                bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        try {
            aliceSessionBuilder.process(bobPreKey);
            throw new AssertionError("Should fail with missing signed prekey!");
        } catch (InvalidKeyException e) {
            // Good!
            return;
        }
    }

    @Test
    public void signedBundleMessage_test() throws InvalidKeyException,
            UntrustedIdentityException,
            InvalidVersionException,
            InvalidMessageException,
            InvalidKeyIdException,
            DuplicateMessageException,
            LegacyMessageException,
            NoSessionException,
            SodiumException, UnsupportedEncodingException {

        ProtocolStore aliceStore = new SSIProtocolStore(ALICE_DID);
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);
        ProtocolStore bobStore = new SSIProtocolStore(BOB_DID);

        ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
        byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().getBytes());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        aliceSessionBuilder.process(bobPreKey);

        String originalMessage = "L'homme est condamné à être libre";
        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());
        CiphertextMessage outgoingMessageTwo = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);
        assertTrue(outgoingMessageTwo.getType() == CiphertextMessage.PREKEY_TYPE);

        PreKeyMessage incomingMessage = new PreKeyMessage(outgoingMessageOne.serialize());

        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);
        assertTrue(originalMessage.equals(new String(plaintext)));

        CiphertextMessage bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new Message(bobOutgoingMessage.serialize()));
        assertTrue(originalMessage.equals(new String(alicePlaintext)));

        // The test

        PreKeyMessage incomingMessageTwo = new PreKeyMessage(outgoingMessageTwo.serialize());

        plaintext = bobSessionCipher.decrypt(new PreKeyMessage(incomingMessageTwo.serialize()));
        assertTrue(originalMessage.equals(new String(plaintext)));

        bobOutgoingMessage = bobSessionCipher.encrypt(originalMessage.getBytes());
        alicePlaintext = aliceSessionCipher.decrypt(new Message(bobOutgoingMessage.serialize()));
        assertTrue(originalMessage.equals(new String(alicePlaintext)));

    }

    @Test
    public void testBadMessageBundle() throws InvalidKeyException,
            UntrustedIdentityException,
            InvalidVersionException,
            InvalidMessageException,
            DuplicateMessageException,
            LegacyMessageException,
            InvalidKeyIdException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);

        ProtocolStore bobStore = new SSIProtocolStore();

        ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
        byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().getBytes());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                31337, bobPreKeyPair.getPublicKey(),
                22, bobSignedPreKeyPair.getPublicKey(), bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        aliceSessionBuilder.process(bobPreKey);

        String originalMessage = "L'homme est condamné à être libre";
        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        CiphertextMessage outgoingMessageOne = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(outgoingMessageOne.getType() == CiphertextMessage.PREKEY_TYPE);

        byte[] goodMessage = outgoingMessageOne.serialize();
        byte[] badMessage = new byte[goodMessage.length];
        System.arraycopy(goodMessage, 0, badMessage, 0, badMessage.length);

        badMessage[badMessage.length - 10] ^= 0x01;

        PreKeyMessage incomingMessage = new PreKeyMessage(badMessage);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        byte[] plaintext = new byte[0];

        try {
            plaintext = bobSessionCipher.decrypt(incomingMessage);
            throw new AssertionError("Decrypt should have failed!");
        } catch (InvalidMessageException e) {
            // good.
        }

        assertTrue(bobStore.containsPreKey(31337));

        plaintext = bobSessionCipher.decrypt(new PreKeyMessage(goodMessage));

        assertTrue(originalMessage.equals(new String(plaintext)));
        assertTrue(!bobStore.containsPreKey(31337));
    }

    @Test
    public void testOptionalOneTimePreKey() throws Exception {
        ProtocolStore aliceStore = new SSIProtocolStore();
        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);

        ProtocolStore bobStore = new SSIProtocolStore();

        ECKeyPair bobPreKeyPair = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();
        byte[] bobSignedPreKeySignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKeyPair.getPublicKey().getBytes());

        PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.getLocalRegistrationId(), 1,
                0, null,
                22, bobSignedPreKeyPair.getPublicKey(),
                bobSignedPreKeySignature,
                bobStore.getIdentityKeyPair().getPublicKey());

        aliceSessionBuilder.process(bobPreKey);

        assertTrue(aliceStore.containsSession(BOB_DID));
        assertTrue(aliceStore.loadSession(BOB_DID).getSessionState().getSessionVersion() == 3);

        String originalMessage = "L'homme est condamné à être libre";
        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        CiphertextMessage outgoingMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(outgoingMessage.getType() == CiphertextMessage.PREKEY_TYPE);

        PreKeyMessage incomingMessage = new PreKeyMessage(outgoingMessage.serialize());
        assertTrue(!incomingMessage.getPreKeyId().isPresent());

        bobStore.storePreKey(31337, new PreKeyRecord(bobPreKey.getPreKeyId(), bobPreKeyPair));
        bobStore.storeSignedPreKey(22, new SignedPreKeyRecord(22, System.currentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);
        byte[] plaintext = bobSessionCipher.decrypt(incomingMessage);

        assertTrue(bobStore.containsSession(ALICE_DID));
        assertTrue(bobStore.loadSession(ALICE_DID).getSessionState().getSessionVersion() == 3);
        assertTrue(bobStore.loadSession(ALICE_DID).getSessionState().getAliceBaseKey() != null);
        assertTrue(originalMessage.equals(new String(plaintext)));
    }


    private void runInteraction(ProtocolStore aliceStore, ProtocolStore bobStore)
            throws DuplicateMessageException,
            LegacyMessageException,
            InvalidMessageException,
            NoSessionException,
            UntrustedIdentityException {

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        String originalMessage = "hello caracola";
        CiphertextMessage aliceMessage = aliceSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(aliceMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        byte[] plaintext = bobSessionCipher.decrypt(new Message(aliceMessage.serialize()));
        assertTrue(new String(plaintext).equals(originalMessage));

        CiphertextMessage bobMessage = bobSessionCipher.encrypt(originalMessage.getBytes());

        assertTrue(bobMessage.getType() == CiphertextMessage.WHISPER_TYPE);

        plaintext = aliceSessionCipher.decrypt(new Message(bobMessage.serialize()));
        assertTrue(new String(plaintext).equals(originalMessage));

        for (int i = 0; i < 10; i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = bobSessionCipher.decrypt(new Message(aliceLoopingMessage.serialize()));
            assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (int i = 0; i < 10; i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = aliceSessionCipher.decrypt(new Message(bobLoopingMessage.serialize()));
            assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        Set<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<>();

        for (int i = 0; i < 10; i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            aliceOutOfOrderMessages.add(new Pair<>(loopingMessage, aliceLoopingMessage));
        }

        for (int i = 0; i < 10; i++) {
            String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                    "We mean that man first of all exists, encounters himself, " +
                    "surges up in the world--and defines himself aftward. " + i);
            CiphertextMessage aliceLoopingMessage = aliceSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = bobSessionCipher.decrypt(new Message(aliceLoopingMessage.serialize()));
            assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (int i = 0; i < 10; i++) {
            String loopingMessage = ("You can only desire based on what you know: " + i);
            CiphertextMessage bobLoopingMessage = bobSessionCipher.encrypt(loopingMessage.getBytes());

            byte[] loopingPlaintext = aliceSessionCipher.decrypt(new Message(bobLoopingMessage.serialize()));
            assertTrue(new String(loopingPlaintext).equals(loopingMessage));
        }

        for (Pair<String, CiphertextMessage> aliceOutOfOrderMessage : aliceOutOfOrderMessages) {
            byte[] outOfOrderPlaintext = bobSessionCipher.decrypt(new Message(aliceOutOfOrderMessage.second().serialize()));
            assertTrue(new String(outOfOrderPlaintext).equals(aliceOutOfOrderMessage.first()));
        }
    }
}
