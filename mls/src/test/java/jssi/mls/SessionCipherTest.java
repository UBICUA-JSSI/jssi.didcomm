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
import jssi.mls.ratchet.AliceProtocolParameters;
import jssi.mls.ratchet.BobProtocolParameters;
import jssi.mls.ratchet.RatchetingSession;
import jssi.mls.state.ProtocolStore;
import jssi.mls.state.SessionRecord;
import jssi.mls.state.SessionState;
import jssi.mls.util.guava.Optional;
import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertTrue;


public class SessionCipherTest {

    public SessionCipherTest(){
        NaCl.sodium();
    }

    @Test
    public void basicSession_test()
            throws InvalidKeyException,
            DuplicateMessageException,
            LegacyMessageException,
            InvalidMessageException,
            NoSessionException,
            UntrustedIdentityException,
            SodiumException {

        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessions(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());
        runInteraction(aliceSessionRecord, bobSessionRecord);
    }

    @Test
    public void messageKeyLimits_test() throws Exception {
        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessions(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

        ProtocolStore aliceStore = new SSIProtocolStore();
        ProtocolStore bobStore = new SSIProtocolStore();

        aliceStore.storeSession(new ProtocolAddress("8EbSkWapRpCAoGepayMY7y", 1), aliceSessionRecord);
        bobStore.storeSession(new ProtocolAddress("KHegADqTR3HZFJUS2nHDzD", 1), bobSessionRecord);

        SessionCipher aliceCipher = new SessionCipher(aliceStore, new ProtocolAddress("8EbSkWapRpCAoGepayMY7y", 1));
        SessionCipher bobCipher = new SessionCipher(bobStore, new ProtocolAddress("KHegADqTR3HZFJUS2nHDzD", 1));

        List<CiphertextMessage> inflight = new LinkedList<>();

        for (int i = 0; i < 2010; i++) {
            inflight.add(aliceCipher.encrypt("you've never been so hungry, you've never been so cold".getBytes()));
        }

        bobCipher.decrypt(new Message(inflight.get(1000).serialize()));
        bobCipher.decrypt(new Message(inflight.get(inflight.size() - 1).serialize()));

        try {
            bobCipher.decrypt(new Message(inflight.get(0).serialize()));
            throw new AssertionError("Should have failed!");
        } catch (DuplicateMessageException dme) {
            // good
        }
    }

    private void runInteraction(SessionRecord aliceSessionRecord, SessionRecord bobSessionRecord)
            throws DuplicateMessageException,
            LegacyMessageException,
            InvalidMessageException,
            NoSessionException,
            UntrustedIdentityException,
            SodiumException {

        ProtocolStore aliceStore = new SSIProtocolStore();
        ProtocolStore bobStore = new SSIProtocolStore();

        aliceStore.storeSession(new ProtocolAddress("8EbSkWapRpCAoGepayMY7y", 1), aliceSessionRecord);
        bobStore.storeSession(new ProtocolAddress("KHegADqTR3HZFJUS2nHDzD", 1), bobSessionRecord);

        SessionCipher aliceCipher = new SessionCipher(aliceStore, new ProtocolAddress("8EbSkWapRpCAoGepayMY7y", 1));
        SessionCipher bobCipher = new SessionCipher(bobStore, new ProtocolAddress("KHegADqTR3HZFJUS2nHDzD", 1));

        byte[] alicePlaintext = "This is a plaintext message.".getBytes();
        CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
        byte[] bobPlaintext = bobCipher.decrypt(new Message(message.serialize()));

        assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));

        byte[] bobReply = "This is a message from Bob.".getBytes();
        CiphertextMessage reply = bobCipher.encrypt(bobReply);
        byte[] receivedReply = aliceCipher.decrypt(new Message(reply.serialize()));

        assertTrue(Arrays.equals(bobReply, receivedReply));

        List<CiphertextMessage> aliceCiphertextMessages = new ArrayList<>();
        List<byte[]> alicePlaintextMessages = new ArrayList<>();

        for (int i = 0; i < 50; i++) {
            alicePlaintextMessages.add(("hola caracola " + i).getBytes());
            aliceCiphertextMessages.add(aliceCipher.encrypt(("hola caracola " + i).getBytes()));
        }

        long seed = System.currentTimeMillis();

        Collections.shuffle(aliceCiphertextMessages, new Random(seed));
        Collections.shuffle(alicePlaintextMessages, new Random(seed));

        for (int i = 0; i < aliceCiphertextMessages.size() / 2; i++) {
            byte[] receivedPlaintext = bobCipher.decrypt(new Message(aliceCiphertextMessages.get(i).serialize()));
            assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages.get(i)));
        }

        List<CiphertextMessage> bobCiphertextMessages = new ArrayList<>();
        List<byte[]> bobPlaintextMessages = new ArrayList<>();

        for (int i = 0; i < 20; i++) {
            bobPlaintextMessages.add(("hola caracola " + i).getBytes());
            bobCiphertextMessages.add(bobCipher.encrypt(("hola caracola " + i).getBytes()));
        }

        seed = System.currentTimeMillis();

        Collections.shuffle(bobCiphertextMessages, new Random(seed));
        Collections.shuffle(bobPlaintextMessages, new Random(seed));

        for (int i = 0; i < bobCiphertextMessages.size() / 2; i++) {
            byte[] receivedPlaintext = aliceCipher.decrypt(new Message(bobCiphertextMessages.get(i).serialize()));
            assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages.get(i)));
        }

        for (int i = aliceCiphertextMessages.size() / 2; i < aliceCiphertextMessages.size(); i++) {
            byte[] receivedPlaintext = bobCipher.decrypt(new Message(aliceCiphertextMessages.get(i).serialize()));
            assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages.get(i)));
        }

        for (int i = bobCiphertextMessages.size() / 2; i < bobCiphertextMessages.size(); i++) {
            byte[] receivedPlaintext = aliceCipher.decrypt(new Message(bobCiphertextMessages.get(i).serialize()));
            assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages.get(i)));
        }
    }


    private void initializeSessions(SessionState aliceSessionState, SessionState bobSessionState)
            throws InvalidKeyException,
            SodiumException {

        ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                aliceIdentityKeyPair.getPrivateKey());
        ECKeyPair aliceBaseKey = Curve.generateKeyPair();
        ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

        ECKeyPair alicePreKey = aliceBaseKey;

        ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                bobIdentityKeyPair.getPrivateKey());
        ECKeyPair bobBaseKey = Curve.generateKeyPair();
        ECKeyPair bobEphemeralKey = bobBaseKey;

        ECKeyPair bobPreKey = Curve.generateKeyPair();

        AliceProtocolParameters aliceParameters = AliceProtocolParameters.newBuilder()
                .setOurBaseKey(aliceBaseKey)
                .setOurIdentityKey(aliceIdentityKey)
                .setTheirOneTimePreKey(Optional.absent())
                .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                .setTheirSignedPreKey(bobBaseKey.getPublicKey())
                .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                .create();

        BobProtocolParameters bobParameters = BobProtocolParameters.newBuilder()
                .setOurRatchetKey(bobEphemeralKey)
                .setOurSignedPreKey(bobBaseKey)
                .setOurOneTimePreKey(Optional.absent())
                .setOurIdentityKey(bobIdentityKey)
                .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                .setTheirBaseKey(aliceBaseKey.getPublicKey())
                .create();

        RatchetingSession.initializeSession(aliceSessionState, aliceParameters);
        RatchetingSession.initializeSession(bobSessionState, bobParameters);
    }

}
