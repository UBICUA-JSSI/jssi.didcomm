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

package jssi.mls.groups;

import org.junit.jupiter.api.Test;

import jssi.mls.ProtocolAddress;
import jssi.mls.DuplicateMessageException;
import jssi.mls.InvalidMessageException;
import jssi.mls.LegacyMessageException;
import jssi.mls.NoSessionException;
import jssi.mls.protocol.SenderKeyDistributionMessage;
import org.libsodium.jni.NaCl;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GroupCipherTest {

    private static final ProtocolAddress SENDER_ADDRESS = new ProtocolAddress("+14150001111", 1);
    private static final SenderKeyName GROUP_SENDER = new SenderKeyName("nihilist history reading group", SENDER_ADDRESS);

    public GroupCipherTest(){
        NaCl.sodium();
    }

    @Test
    public void noSession_test() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
        GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

        SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
        SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

//    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("hola caracola".getBytes());
        try {
            byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);
            throw new AssertionError("Should be no session!");
        } catch (NoSessionException e) {
            // good
        }
    }

    @Test
    public void basicEncryptDecrypt_test()
            throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
        GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

        SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
        SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
        bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("hola caracola".getBytes());
        byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

        assertTrue(new String(plaintextFromAlice).equals("hola caracola"));
    }

    @Test
    public void largeMessages_test() throws InvalidMessageException, LegacyMessageException, NoSessionException, DuplicateMessageException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER);
        GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER);

        SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER);
        SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
        bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

        byte[] plaintext = new byte[1024 * 1024];
        new Random().nextBytes(plaintext);

        byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(plaintext);
        byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

        assertTrue(Arrays.equals(plaintext, plaintextFromAlice));
    }

    @Test
    public void basicRatchet_test()
            throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
        GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage sentAliceDistributionMessage =
                aliceSessionBuilder.create(aliceName);
        SenderKeyDistributionMessage receivedAliceDistributionMessage =
                new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());

        bobSessionBuilder.process(aliceName, receivedAliceDistributionMessage);

        byte[] ciphertextFromAlice = aliceGroupCipher.encrypt("hola caracola".getBytes());
        byte[] ciphertextFromAlice2 = aliceGroupCipher.encrypt("hola caracola2".getBytes());
        byte[] ciphertextFromAlice3 = aliceGroupCipher.encrypt("hola caracola3".getBytes());

        byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

        try {
            bobGroupCipher.decrypt(ciphertextFromAlice);
            throw new AssertionError("Should have ratcheted forward!");
        } catch (DuplicateMessageException dme) {
            // good
        }

        byte[] plaintextFromAlice2 = bobGroupCipher.decrypt(ciphertextFromAlice2);
        byte[] plaintextFromAlice3 = bobGroupCipher.decrypt(ciphertextFromAlice3);

        assertTrue(new String(plaintextFromAlice).equals("hola caracola"));
        assertTrue(new String(plaintextFromAlice2).equals("hola caracola2"));
        assertTrue(new String(plaintextFromAlice3).equals("hola caracola3"));
    }

    @Test
    public void lateJoin_test() throws NoSessionException, InvalidMessageException, LegacyMessageException, DuplicateMessageException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);


        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);

        SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);
        // Send off to some people.

        for (int i = 0; i < 100; i++) {
            aliceGroupCipher.encrypt("up the punks up the punks up the punks".getBytes());
        }

        // Now Bob Joins.
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
        GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage distributionMessageToBob = aliceSessionBuilder.create(aliceName);
        bobSessionBuilder.process(aliceName, new SenderKeyDistributionMessage(distributionMessageToBob.serialize()));

        byte[] ciphertext = aliceGroupCipher.encrypt("welcome to the group".getBytes());
        byte[] plaintext = bobGroupCipher.decrypt(ciphertext);

        assertEquals(new String(plaintext), "welcome to the group");
    }

    @Test
    public void outOfOrder_test()  throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
        GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        ArrayList<byte[]> ciphertexts = new ArrayList<>(100);

        for (int i = 0; i < 100; i++) {
            ciphertexts.add(aliceGroupCipher.encrypt("up the punks".getBytes()));
        }

        while (ciphertexts.size() > 0) {
            int index = randomInt() % ciphertexts.size();
            byte[] ciphertext = ciphertexts.remove(index);
            byte[] plaintext = bobGroupCipher.decrypt(ciphertext);

            assertTrue(new String(plaintext).equals("up the punks"));
        }
    }

    @Test
    public void encryptNoSession_test() {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, new SenderKeyName("coolio groupio", new ProtocolAddress("+10002223333", 1)));
        try {
            aliceGroupCipher.encrypt("up the punks".getBytes());
            throw new AssertionError("Should have failed!");
        } catch (NoSessionException nse) {
            // good
        }
    }


    @Test
    public void tooFarInFuture_test() throws DuplicateMessageException, InvalidMessageException, LegacyMessageException, NoSessionException {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
        GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        for (int i = 0; i < 2001; i++) {
            aliceGroupCipher.encrypt("up the punks".getBytes());
        }

        byte[] tooFarCiphertext = aliceGroupCipher.encrypt("notta gonna worka".getBytes());
        try {
            bobGroupCipher.decrypt(tooFarCiphertext);
            throw new AssertionError("Should have failed!");
        } catch (InvalidMessageException e) {
            // good
        }
    }

    @Test
    public void messageKeyLimit_test() throws Exception {
        InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
        InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

        GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
        GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

        SenderKeyName aliceName = GROUP_SENDER;

        GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
        GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

        SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.create(aliceName);

        bobSessionBuilder.process(aliceName, aliceDistributionMessage);

        List<byte[]> inflight = new LinkedList<>();

        for (int i = 0; i < 2010; i++) {
            inflight.add(aliceGroupCipher.encrypt("up the punks".getBytes()));
        }

        bobGroupCipher.decrypt(inflight.get(1000));
        bobGroupCipher.decrypt(inflight.get(inflight.size() - 1));

        try {
            bobGroupCipher.decrypt(inflight.get(0));
            throw new AssertionError("Should have failed!");
        } catch (DuplicateMessageException e) {
            // good
        }
    }


    private int randomInt() {
        try {
            return SecureRandom.getInstance("SHA1PRNG").nextInt(Integer.MAX_VALUE);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
