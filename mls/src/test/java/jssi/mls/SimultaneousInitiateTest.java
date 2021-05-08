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

import jssi.mls.protocol.Message;
import jssi.mls.protocol.PreKeyMessage;
import org.junit.jupiter.api.Test;

import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;
import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.protocol.CiphertextMessage;
import jssi.mls.state.ProtocolStore;
import jssi.mls.state.PreKeyBundle;
import jssi.mls.state.PreKeyRecord;
import jssi.mls.state.SignedPreKeyRecord;
import jssi.mls.util.Medium;

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public class SimultaneousInitiateTest {

    private static final ProtocolAddress BOB_DID = new ProtocolAddress("KHegADqTR3HZFJUS2nHDzD", 1);
    private static final ProtocolAddress ALICE_DID = new ProtocolAddress("8EbSkWapRpCAoGepayMY7y", 1);

    private static ECKeyPair aliceSignedPreKey = null;
    private static ECKeyPair bobSignedPreKey = null;

    public SimultaneousInitiateTest() {
        try {
            NaCl.sodium();
            aliceSignedPreKey = Curve.generateKeyPair();
            bobSignedPreKey = Curve.generateKeyPair();
        } catch (SodiumException e) {
            e.printStackTrace();
        }
    }


    private static final int aliceSignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
    private static final int bobSignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);

    @Test
    public void basicSimultaneousInitiate_test()
            throws InvalidKeyException,
            UntrustedIdentityException,
            InvalidVersionException,
            InvalidMessageException,
            DuplicateMessageException,
            LegacyMessageException,
            InvalidKeyIdException,
            NoSessionException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore(ALICE_DID);
        ProtocolStore bobStore = new SSIProtocolStore(BOB_DID);

        PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_DID);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertEquals(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
        assertEquals(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());

        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyMessage(messageForAlice.serialize()));
        byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyMessage(messageForBob.serialize()));

        assertEquals(new String(alicePlaintext), "sample message");
        assertEquals(new String(bobPlaintext), "hey there");
        assertEquals(aliceStore.loadSession(BOB_DID).getSessionState().getSessionVersion(), 3);
        assertEquals(bobStore.loadSession(ALICE_DID).getSessionState().getSessionVersion(), 3);
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

        byte[] responsePlaintext = bobSessionCipher.decrypt(new Message(aliceResponse.serialize()));

        assertEquals(new String(responsePlaintext), "second message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new Message(finalMessage.serialize()));

        assertEquals(new String(finalPlaintext), "third message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void lostSimultaneousInitiate_test()
            throws InvalidKeyException,
            UntrustedIdentityException,
            InvalidVersionException,
            InvalidMessageException,
            DuplicateMessageException,
            LegacyMessageException,
            InvalidKeyIdException,
            NoSessionException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore(ALICE_DID);
        ProtocolStore bobStore = new SSIProtocolStore(BOB_DID);

        PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_DID);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertEquals(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
        assertEquals(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyMessage(messageForBob.serialize()));

        assertEquals(new String(bobPlaintext), "hey there");
        assertEquals(bobStore.loadSession(ALICE_DID).getSessionState().getSessionVersion(), 3);

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertEquals(CiphertextMessage.PREKEY_TYPE, aliceResponse.getType());

        byte[] responsePlaintext = bobSessionCipher.decrypt(new PreKeyMessage(aliceResponse.serialize()));

        assertEquals(new String(responsePlaintext), "second message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new Message(finalMessage.serialize()));

        assertEquals(new String(finalPlaintext), "third message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }
    @Test
    public void simultaneousInitiateLostMessage_test()
            throws InvalidKeyException,
            UntrustedIdentityException,
            InvalidVersionException,
            InvalidMessageException,
            DuplicateMessageException,
            LegacyMessageException,
            InvalidKeyIdException,
            NoSessionException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore(ALICE_DID);
        ProtocolStore bobStore = new SSIProtocolStore(BOB_DID);

        PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_DID);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertEquals(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
        assertEquals(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyMessage(messageForAlice.serialize()));
        byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyMessage(messageForBob.serialize()));

        assertEquals(new String(alicePlaintext), "sample message");
        assertEquals(new String(bobPlaintext), "hey there");
        assertEquals(aliceStore.loadSession(BOB_DID).getSessionState().getSessionVersion(), 3);
        assertEquals(bobStore.loadSession(ALICE_DID).getSessionState().getSessionVersion(), 3);
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new Message(finalMessage.serialize()));

        assertEquals(new String(finalPlaintext), "third message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void simultaneousInitiateRepeatedMessages_test()
            throws InvalidKeyException,
            UntrustedIdentityException,
            InvalidVersionException,
            InvalidMessageException,
            DuplicateMessageException,
            LegacyMessageException,
            InvalidKeyIdException,
            NoSessionException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore(ALICE_DID);
        ProtocolStore bobStore = new SSIProtocolStore(BOB_DID);

        PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
        PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_DID);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        aliceSessionBuilder.process(bobPreKeyBundle);
        bobSessionBuilder.process(alicePreKeyBundle);

        CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
        CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

        assertEquals(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
        assertEquals(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyMessage(messageForAlice.serialize()));
        byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyMessage(messageForBob.serialize()));

        assertEquals(new String(alicePlaintext), "sample message");
        assertEquals(new String(bobPlaintext), "hey there");
        assertEquals(aliceStore.loadSession(BOB_DID).getSessionState().getSessionVersion(), 3);
        assertEquals(bobStore.loadSession(ALICE_DID).getSessionState().getSessionVersion(), 3);
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        for (int i = 0; i < 50; i++) {
            CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertEquals(CiphertextMessage.WHISPER_TYPE, messageForBobRepeat.getType());
            assertEquals(CiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.getType());
            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new Message(messageForAliceRepeat.serialize()));
            byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new Message(messageForBobRepeat.serialize()));

            assertEquals(new String(alicePlaintextRepeat), "sample message");
            assertEquals(new String(bobPlaintextRepeat), "hey there");
            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

        byte[] responsePlaintext = bobSessionCipher.decrypt(new Message(aliceResponse.serialize()));

        assertEquals(new String(responsePlaintext), "second message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new Message(finalMessage.serialize()));

        assertEquals(new String(finalPlaintext), "third message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void repeatedSimultaneousInitiateRepeatedMessages_test()
            throws InvalidKeyException,
            UntrustedIdentityException,
            InvalidVersionException,
            InvalidMessageException,
            DuplicateMessageException,
            LegacyMessageException,
            InvalidKeyIdException,
            NoSessionException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore(ALICE_DID);
        ProtocolStore bobStore = new SSIProtocolStore(BOB_DID);

        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, ALICE_DID);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, BOB_DID);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        for (int i = 0; i < 15; i++) {
            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            assertEquals(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
            assertEquals(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());
            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyMessage(messageForBob.serialize()));

            assertEquals(new String(alicePlaintext), "sample message");
            assertEquals(new String(bobPlaintext), "hey there");
            assertEquals(aliceStore.loadSession(BOB_DID).getSessionState().getSessionVersion(), 3);
            assertEquals(bobStore.loadSession(ALICE_DID).getSessionState().getSessionVersion(), 3);
            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        for (int i = 0; i < 50; i++) {
            CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertEquals(CiphertextMessage.WHISPER_TYPE, messageForBobRepeat.getType());
            assertEquals(CiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.getType());
            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new Message(messageForAliceRepeat.serialize()));
            byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new Message(messageForBobRepeat.serialize()));

            assertEquals(new String(alicePlaintextRepeat), "sample message");
            assertEquals(new String(bobPlaintextRepeat), "hey there");
            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

        byte[] responsePlaintext = bobSessionCipher.decrypt(new Message(aliceResponse.serialize()));

        assertEquals(new String(responsePlaintext), "second message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new Message(finalMessage.serialize()));

        assertEquals(new String(finalPlaintext), "third message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    @Test
    public void repeatedSimultaneousInitiateLostMessageRepeatedMessages_test()
            throws InvalidKeyException,
            UntrustedIdentityException,
            InvalidVersionException,
            InvalidMessageException,
            DuplicateMessageException,
            LegacyMessageException,
            InvalidKeyIdException,
            NoSessionException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore();
        ProtocolStore bobStore = new SSIProtocolStore();


        SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_DID);
        SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_DID);

        SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_DID);
        SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_DID);

        PreKeyBundle bobLostPreKeyBundle = createBobPreKeyBundle(bobStore);
        aliceSessionBuilder.process(bobLostPreKeyBundle);
        CiphertextMessage lostMessageForBob = aliceSessionCipher.encrypt("hey there".getBytes());

        for (int i = 0; i < 15; i++) {
            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            assertEquals(CiphertextMessage.PREKEY_TYPE, messageForBob.getType());
            assertEquals(CiphertextMessage.PREKEY_TYPE, messageForAlice.getType());
            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeyMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeyMessage(messageForBob.serialize()));

            assertEquals(new String(alicePlaintext), "sample message");
            assertEquals(new String(bobPlaintext), "hey there");
            assertEquals(aliceStore.loadSession(BOB_DID).getSessionState().getSessionVersion(), 3);
            assertEquals(bobStore.loadSession(ALICE_DID).getSessionState().getSessionVersion(), 3);
            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        for (int i = 0; i < 50; i++) {
            CiphertextMessage messageForBobRepeat = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAliceRepeat = bobSessionCipher.encrypt("sample message".getBytes());

            assertEquals(CiphertextMessage.WHISPER_TYPE, messageForBobRepeat.getType());
            assertEquals(CiphertextMessage.WHISPER_TYPE, messageForAliceRepeat.getType());
            assertFalse(isSessionIdEqual(aliceStore, bobStore));

            byte[] alicePlaintextRepeat = aliceSessionCipher.decrypt(new Message(messageForAliceRepeat.serialize()));
            byte[] bobPlaintextRepeat = bobSessionCipher.decrypt(new Message(messageForBobRepeat.serialize()));

            assertEquals(new String(alicePlaintextRepeat), "sample message");
            assertEquals(new String(bobPlaintextRepeat), "hey there");
            assertFalse(isSessionIdEqual(aliceStore, bobStore));
        }

        CiphertextMessage aliceResponse = aliceSessionCipher.encrypt("second message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, aliceResponse.getType());

        byte[] responsePlaintext = bobSessionCipher.decrypt(new Message(aliceResponse.serialize()));

        assertEquals(new String(responsePlaintext), "second message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage finalMessage = bobSessionCipher.encrypt("third message".getBytes());

        assertEquals(CiphertextMessage.WHISPER_TYPE, finalMessage.getType());

        byte[] finalPlaintext = aliceSessionCipher.decrypt(new Message(finalMessage.serialize()));

        assertEquals(new String(finalPlaintext), "third message");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));

        byte[] lostMessagePlaintext = bobSessionCipher.decrypt(new PreKeyMessage(lostMessageForBob.serialize()));

        assertEquals(new String(lostMessagePlaintext), "hey there");
        assertFalse(isSessionIdEqual(aliceStore, bobStore));

        CiphertextMessage blastFromThePast = bobSessionCipher.encrypt("unexpected!".getBytes());
        byte[] blastFromThePastPlaintext = aliceSessionCipher.decrypt(new Message(blastFromThePast.serialize()));

        assertEquals(new String(blastFromThePastPlaintext), "unexpected!");
        assertTrue(isSessionIdEqual(aliceStore, bobStore));
    }

    private boolean isSessionIdEqual(ProtocolStore aliceStore, ProtocolStore bobStore) {
        return Arrays.equals(aliceStore.loadSession(BOB_DID).getSessionState().getAliceBaseKey(),
                bobStore.loadSession(ALICE_DID).getSessionState().getAliceBaseKey());
    }

    private PreKeyBundle createAlicePreKeyBundle(ProtocolStore aliceStore) throws InvalidKeyException, SodiumException {
        ECKeyPair aliceUnsignedPreKey = Curve.generateKeyPair();
        int aliceUnsignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
        byte[] aliceSignature = Curve.calculateSignature(aliceStore.getIdentityKeyPair().getPrivateKey(),
                aliceSignedPreKey.getPublicKey().getBytes());

        PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
                aliceUnsignedPreKeyId, aliceUnsignedPreKey.getPublicKey(),
                aliceSignedPreKeyId, aliceSignedPreKey.getPublicKey(),
                aliceSignature, aliceStore.getIdentityKeyPair().getPublicKey());

        aliceStore.storeSignedPreKey(aliceSignedPreKeyId, new SignedPreKeyRecord(aliceSignedPreKeyId, System.currentTimeMillis(), aliceSignedPreKey, aliceSignature));
        aliceStore.storePreKey(aliceUnsignedPreKeyId, new PreKeyRecord(aliceUnsignedPreKeyId, aliceUnsignedPreKey));

        return alicePreKeyBundle;
    }

    private PreKeyBundle createBobPreKeyBundle(ProtocolStore bobStore) throws InvalidKeyException, SodiumException {
        ECKeyPair bobUnsignedPreKey = Curve.generateKeyPair();
        int bobUnsignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
        byte[] bobSignature = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKey.getPublicKey().getBytes());

        PreKeyBundle bobPreKeyBundle = new PreKeyBundle(1, 1,
                bobUnsignedPreKeyId, bobUnsignedPreKey.getPublicKey(),
                bobSignedPreKeyId, bobSignedPreKey.getPublicKey(),
                bobSignature, bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId, System.currentTimeMillis(), bobSignedPreKey, bobSignature));
        bobStore.storePreKey(bobUnsignedPreKeyId, new PreKeyRecord(bobUnsignedPreKeyId, bobUnsignedPreKey));

        return bobPreKeyBundle;
    }
}
