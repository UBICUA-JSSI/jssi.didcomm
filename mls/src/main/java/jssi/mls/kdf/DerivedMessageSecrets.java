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

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;

public class DerivedMessageSecrets {

  public  static final int SIZE              = 80;
  private static final int CIPHER_KEY_LENGTH = 32;
  private static final int MAC_KEY_LENGTH    = 32;
  private static final int IV_LENGTH         = 16;

  private final SecretKeySpec   cipherKey;
  private final SecretKeySpec   macKey;
  private final IvParameterSpec iv;

  public DerivedMessageSecrets(byte[] okm) {
    try {
      byte[][] keys = ByteUtil.split(okm, CIPHER_KEY_LENGTH, MAC_KEY_LENGTH, IV_LENGTH);

      this.cipherKey = new SecretKeySpec(keys[0], "AES");
      this.macKey    = new SecretKeySpec(keys[1], "HmacSHA256");
      this.iv        = new IvParameterSpec(keys[2]);
    } catch (ParseException e) {
      throw new AssertionError(e);
    }
  }

  public SecretKeySpec getCipherKey() {
    return cipherKey;
  }

  public SecretKeySpec getMacKey() {
    return macKey;
  }

  public IvParameterSpec getIv() {
    return iv;
  }
}
