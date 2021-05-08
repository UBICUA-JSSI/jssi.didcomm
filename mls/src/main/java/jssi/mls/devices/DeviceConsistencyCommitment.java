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

package jssi.mls.devices;

import jssi.mls.IdentityKey;
import jssi.mls.util.ByteUtil;
import jssi.mls.util.IdentityKeyComparator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DeviceConsistencyCommitment {

  private static final String VERSION = "DeviceConsistencyCommitment_V0";

  private final int generation;
  private final byte[] serialized;

  public DeviceConsistencyCommitment(int generation, List<IdentityKey> identityKeys) {
    try {
      ArrayList<IdentityKey> sortedIdentityKeys = new ArrayList<>(identityKeys);
      Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

      MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
      messageDigest.update(VERSION.getBytes());
      messageDigest.update(ByteUtil.intToByteArray(generation));

      for (IdentityKey commitment : sortedIdentityKeys) {
        messageDigest.update(commitment.getPublicKey().getBytes());
      }

      this.generation = generation;
      this.serialized = messageDigest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] toByteArray() {
    return serialized;
  }

  public int getGeneration() {
    return generation;
  }


}
