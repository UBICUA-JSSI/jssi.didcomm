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

/**
 * An interface describing the local storage of {@link PreKeyRecord}s.
 *
 * @author Moxie Marlinspike
 */
public interface PreKeyStore {

  /**
   * Load a local PreKeyRecord.
   *
   * @param preKeyId the ID of the local PreKeyRecord.
   * @return the corresponding PreKeyRecord.
   * @throws InvalidKeyIdException when there is no corresponding PreKeyRecord.
   */
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException;

  /**
   * Store a local PreKeyRecord.
   *
   * @param preKeyId the ID of the PreKeyRecord to store.
   * @param record the PreKeyRecord.
   */
  public void         storePreKey(int preKeyId, PreKeyRecord record);

  /**
   * @param preKeyId A PreKeyRecord ID.
   * @return true if the store has a record for the preKeyId, otherwise false.
   */
  public boolean      containsPreKey(int preKeyId);

  /**
   * Delete a PreKeyRecord from local storage.
   *
   * @param preKeyId The ID of the PreKeyRecord to remove.
   */
  public void         removePreKey(int preKeyId);

}
