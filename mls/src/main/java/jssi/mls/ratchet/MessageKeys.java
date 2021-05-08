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
package jssi.mls.ratchet;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MessageKeys {

    private final SecretKeySpec cipherKey;
    private final SecretKeySpec macKey;
    private final IvParameterSpec iv;
    private final int counter;

    public MessageKeys(SecretKeySpec cipherKey, SecretKeySpec macKey, IvParameterSpec iv, int counter) {
        this.cipherKey = cipherKey;
        this.macKey = macKey;
        this.iv = iv;
        this.counter = counter;
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

    public int getCounter() {
        return counter;
    }
}
