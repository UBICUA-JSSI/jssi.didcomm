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

import jssi.mls.groups.state.SenderKeyRecord;
import jssi.mls.groups.state.SenderKeyStore;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class InMemorySenderKeyStore implements SenderKeyStore {

    private final Map<SenderKeyName, SenderKeyRecord> store = new HashMap<>();

    @Override
    public void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record) {
        store.put(senderKeyName, record);
    }

    @Override
    public SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName) {
        try {
            SenderKeyRecord record = store.get(senderKeyName);

            if (record == null) {
                return new SenderKeyRecord();
            } else {
                return new SenderKeyRecord(record.serialize());
            }
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}
