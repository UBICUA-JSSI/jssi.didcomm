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
package jssi.mls.kdf;

import jssi.mls.util.ByteUtil;

public class DerivedRootSecrets {

  public static final int SIZE = 64;

  private final byte[] rootKey;
  private final byte[] chainKey;

  public DerivedRootSecrets(byte[] okm) {
    byte[][] keys = ByteUtil.split(okm, 32, 32);
    this.rootKey  = keys[0];
    this.chainKey = keys[1];
  }

  public byte[] getRootKey() {
    return rootKey;
  }

  public byte[] getChainKey() {
    return chainKey;
  }

}
