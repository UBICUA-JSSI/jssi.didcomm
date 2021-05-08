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

import jssi.mls.InvalidKeyException;
import jssi.mls.InvalidKeyIdException;
import jssi.mls.groups.state.SenderKeyRecord;
import jssi.mls.groups.state.SenderKeyState;
import jssi.mls.groups.state.SenderKeyStore;
import jssi.mls.protocol.SenderKeyDistributionMessage;
import jssi.mls.util.KeyHelper;
import org.libsodium.jni.SodiumException;

/**
 * GroupSessionBuilder is responsible for setting up group SenderKey encrypted sessions.
 *
 * Once a session has been established, {@link jssi.mls.groups.GroupCipher}
 * can be used to encrypt/decrypt messages in that session.
 * <p>
 * The built sessions are unidirectional: they can be used either for sending or for receiving,
 * but not both.
 *
 * Sessions are constructed per (groupId + senderId + deviceId) tuple.  Remote logical users
 * are identified by their senderId, and each logical recipientId can have multiple physical
 * devices.
 *
 * @author Moxie Marlinspike
 */

public class GroupSessionBuilder {

    private final SenderKeyStore senderKeyStore;

    public GroupSessionBuilder(SenderKeyStore senderKeyStore) {
        this.senderKeyStore = senderKeyStore;
    }

    /**
     * Construct a group session for receiving messages from senderKeyName.
     *
     * @param senderKeyName The (groupId, senderId, deviceId) tuple associated with the SenderKeyDistributionMessage.
     * @param senderKeyDistributionMessage A received SenderKeyDistributionMessage.
     */
    public void process(SenderKeyName senderKeyName, SenderKeyDistributionMessage senderKeyDistributionMessage) {
        synchronized (GroupCipher.LOCK) {
            SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);
            senderKeyRecord.addSenderKeyState(senderKeyDistributionMessage.getId(),
                    senderKeyDistributionMessage.getIteration(),
                    senderKeyDistributionMessage.getChainKey(),
                    senderKeyDistributionMessage.getSignatureKey());
            senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
        }
    }

    /**
     * Construct a group session for sending messages.
     *
     * @param senderKeyName The (groupId, senderId, deviceId) tuple.  In this case, 'senderId' should be the caller.
     * @return A SenderKeyDistributionMessage that is individually distributed to each member of the group.
     */
    public SenderKeyDistributionMessage create(SenderKeyName senderKeyName) {
        synchronized (GroupCipher.LOCK) {
            try {
                SenderKeyRecord senderKeyRecord = senderKeyStore.loadSenderKey(senderKeyName);

                if (senderKeyRecord.isEmpty()) {
                    senderKeyRecord.setSenderKeyState(KeyHelper.generateSenderKeyId(),
                            0,
                            KeyHelper.generateSenderKey(),
                            KeyHelper.generateSenderSigningKey());
                    senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord);
                }

                SenderKeyState state = senderKeyRecord.getSenderKeyState();

                return new SenderKeyDistributionMessage(state.getKeyId(),
                        state.getSenderChainKey().getIteration(),
                        state.getSenderChainKey().getSeed(),
                        state.getSigningKeyPublic());

            } catch (InvalidKeyIdException | InvalidKeyException | SodiumException e) {
                throw new AssertionError(e);
            }
        }
    }
}
