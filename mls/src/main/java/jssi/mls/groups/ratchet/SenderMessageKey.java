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

package jssi.mls.groups.ratchet;

import jssi.mls.kdf.HKDF;
import jssi.mls.util.ByteUtil;

/**
 * The final symmetric material (IV and Cipher Key) used for encrypting
 * individual SenderKey messages.
 *
 * @author Moxie Marlinspike
 */
public class SenderMessageKey {

    private final int iteration;
    private final byte[] iv;
    private final byte[] cipherKey;
    private final byte[] seed;

    public SenderMessageKey(int iteration, byte[] seed) {
        byte[] derivative = new HKDF().deriveSecrets(seed, "WhisperGroup".getBytes(), 48);
        byte[][] parts = ByteUtil.split(derivative, 16, 32);

        this.iteration = iteration;
        this.seed = seed;
        this.iv = parts[0];
        this.cipherKey = parts[1];
    }

    public int getIteration() {
        return iteration;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getCipherKey() {
        return cipherKey;
    }

    public byte[] getSeed() {
        return seed;
    }
}
