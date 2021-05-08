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
package jssi.mls.state.store;

import jssi.mls.InvalidKeyIdException;
import jssi.mls.state.PreKeyRecord;
import jssi.mls.state.PreKeyStore;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class InMemoryPreKeyStore implements PreKeyStore {

    private final Map<Integer, byte[]> store = new HashMap<>();

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        try {
            if (!store.containsKey(preKeyId)) {
                throw new InvalidKeyIdException("No such prekeyrecord!");
            }

            return new PreKeyRecord(store.get(preKeyId));
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        store.put(preKeyId, record.serialize());
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        return store.containsKey(preKeyId);
    }

    @Override
    public void removePreKey(int preKeyId) {
        store.remove(preKeyId);
    }
}
