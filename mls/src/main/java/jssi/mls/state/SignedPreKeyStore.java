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
package jssi.mls.state;

import jssi.mls.InvalidKeyIdException;

import java.util.List;

public interface SignedPreKeyStore {


    /**
     * Load a local SignedPreKeyRecord.
     *
     * @param signedPreKeyId the ID of the local SignedPreKeyRecord.
     * @return the corresponding SignedPreKeyRecord.
     * @throws InvalidKeyIdException when there is no corresponding SignedPreKeyRecord.
     */
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException;

    /**
     * Load all local SignedPreKeyRecords.
     *
     * @return All stored SignedPreKeyRecords.
     */
    public List<SignedPreKeyRecord> loadSignedPreKeys();

    /**
     * Store a local SignedPreKeyRecord.
     *
     * @param signedPreKeyId the ID of the SignedPreKeyRecord to store.
     * @param record the SignedPreKeyRecord.
     */
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record);

    /**
     * @param signedPreKeyId A SignedPreKeyRecord ID.
     * @return true if the store has a record for the signedPreKeyId, otherwise false.
     */
    public boolean containsSignedPreKey(int signedPreKeyId);

    /**
     * Delete a SignedPreKeyRecord from local storage.
     *
     * @param signedPreKeyId The ID of the SignedPreKeyRecord to remove.
     */
    public void removeSignedPreKey(int signedPreKeyId);

}
