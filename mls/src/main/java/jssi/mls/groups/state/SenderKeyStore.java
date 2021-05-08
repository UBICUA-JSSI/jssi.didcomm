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

import jssi.mls.groups.SenderKeyName;

public interface SenderKeyStore {

  /**
   * Commit to storage the {@link jssi.mls.groups.state.SenderKeyRecord} for a
   * given (groupId + senderId + deviceId) tuple.
   *
   * @param senderKeyName the (groupId + senderId + deviceId) tuple.
   * @param record the current SenderKeyRecord for the specified senderKeyName.
   */
  public void storeSenderKey(SenderKeyName senderKeyName, SenderKeyRecord record);

  /**
   * Returns a copy of the {@link jssi.mls.groups.state.SenderKeyRecord}
   * corresponding to the (groupId + senderId + deviceId) tuple, or a new SenderKeyRecord if
   * one does not currently exist.
   * <p>
   * It is important that implementations return a copy of the current durable information.  The
   * returned SenderKeyRecord may be modified, but those changes should not have an effect on the
   * durable session state (what is returned by subsequent calls to this method) without the
   * store method being called here first.
   *
   * @param senderKeyName The (groupId + senderId + deviceId) tuple.
   * @return a copy of the SenderKeyRecord corresponding to the (groupId + senderId + deviceId tuple, or
   *         a new SenderKeyRecord if one does not currently exist.
   */

  public SenderKeyRecord loadSenderKey(SenderKeyName senderKeyName);
}
