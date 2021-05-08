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

import jssi.mls.util.ByteArrayComparator;
import jssi.mls.util.ByteUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class DeviceConsistencyCodeGenerator {

  private static final int CODE_VERSION = 0;

  public static String generateFor(DeviceConsistencyCommitment commitment,
                                   List<DeviceConsistencySignature> signatures)
  {
    try {
      ArrayList<DeviceConsistencySignature> sortedSignatures = new ArrayList<>(signatures);
      Collections.sort(sortedSignatures, new SignatureComparator());

      MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
      messageDigest.update(ByteUtil.shortToByteArray(CODE_VERSION));
      messageDigest.update(commitment.toByteArray());

      for (DeviceConsistencySignature signature : sortedSignatures) {
        messageDigest.update(signature.getVrfOutput());
      }

      byte[] hash = messageDigest.digest();

      String digits = getEncodedChunk(hash, 0) + getEncodedChunk(hash, 5);
      return digits.substring(0, 6);

    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private static String getEncodedChunk(byte[] hash, int offset) {
    long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
    return String.format("%05d", chunk);
  }


  private static class SignatureComparator extends ByteArrayComparator implements Comparator<DeviceConsistencySignature> {
    @Override
    public int compare(DeviceConsistencySignature first, DeviceConsistencySignature second) {
      return compare(first.getVrfOutput(), second.getVrfOutput());
    }
  }
}
