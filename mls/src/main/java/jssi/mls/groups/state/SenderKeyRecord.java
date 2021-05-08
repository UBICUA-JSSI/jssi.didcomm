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

import jssi.mls.InvalidKeyIdException;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.state.StorageProtos;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import jssi.mls.state.StorageProtos.SenderKeyRecordStructure;

/**
 * A durable representation of a set of SenderKeyStates for a specific
 * SenderKeyName.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyRecord {

    private static final int MAX_STATES = 5;

    private LinkedList<SenderKeyState> senderKeyStates = new LinkedList<>();

    public SenderKeyRecord() {
    }

    public SenderKeyRecord(byte[] serialized) throws IOException {
        SenderKeyRecordStructure senderKeyRecordStructure = SenderKeyRecordStructure.parseFrom(serialized);

        for (StorageProtos.SenderKeyStateStructure structure : senderKeyRecordStructure.getSenderKeyStatesList()) {
            this.senderKeyStates.add(new SenderKeyState(structure));
        }
    }

    public boolean isEmpty() {
        return senderKeyStates.isEmpty();
    }

    public SenderKeyState getSenderKeyState() throws InvalidKeyIdException {
        if (!senderKeyStates.isEmpty()) {
            return senderKeyStates.get(0);
        } else {
            throw new InvalidKeyIdException("No key state in record!");
        }
    }

    public SenderKeyState getSenderKeyState(int keyId) throws InvalidKeyIdException {
        for (SenderKeyState state : senderKeyStates) {
            if (state.getKeyId() == keyId) {
                return state;
            }
        }

        throw new InvalidKeyIdException("No keys for: " + keyId);
    }

    public void addSenderKeyState(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
        senderKeyStates.addFirst(new SenderKeyState(id, iteration, chainKey, signatureKey));

        if (senderKeyStates.size() > MAX_STATES) {
            senderKeyStates.removeLast();
        }
    }

    public void setSenderKeyState(int id, int iteration, byte[] chainKey, ECKeyPair signatureKey) {
        senderKeyStates.clear();
        senderKeyStates.add(new SenderKeyState(id, iteration, chainKey, signatureKey));
    }

    public byte[] serialize() {
        SenderKeyRecordStructure.Builder recordStructure = SenderKeyRecordStructure.newBuilder();

        for (SenderKeyState senderKeyState : senderKeyStates) {
            recordStructure.addSenderKeyStates(senderKeyState.getStructure());
        }

        return recordStructure.build().toByteArray();
    }
}
