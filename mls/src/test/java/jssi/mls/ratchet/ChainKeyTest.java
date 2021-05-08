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

import org.junit.jupiter.api.Test;

import jssi.mls.kdf.HKDF;
import org.libsodium.jni.NaCl;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ChainKeyTest {

    public ChainKeyTest(){
        NaCl.sodium();
    }

    @Test
    public void chainKeyDerivation_test(){

        byte[] seed = {
                (byte) 0x8a, (byte) 0xb7, (byte) 0x2d, (byte) 0x6f, (byte) 0x4c,
                (byte) 0xc5, (byte) 0xac, (byte) 0x0d, (byte) 0x38, (byte) 0x7e,
                (byte) 0xaf, (byte) 0x46, (byte) 0x33, (byte) 0x78, (byte) 0xdd,
                (byte) 0xb2, (byte) 0x8e, (byte) 0xdd, (byte) 0x07, (byte) 0x38,
                (byte) 0x5b, (byte) 0x1c, (byte) 0xb0, (byte) 0x12, (byte) 0x50,
                (byte) 0xc7, (byte) 0x15, (byte) 0x98, (byte) 0x2e, (byte) 0x7a,
                (byte) 0xd4, (byte) 0x8f};

        byte[] messageKey = {
                /* (byte) 0x02*/
                (byte) 0xbf, (byte) 0x51, (byte) 0xe9, (byte) 0xd7,
                (byte) 0x5e, (byte) 0x0e, (byte) 0x31, (byte) 0x03, (byte) 0x10,
                (byte) 0x51, (byte) 0xf8, (byte) 0x2a, (byte) 0x24, (byte) 0x91,
                (byte) 0xff, (byte) 0xc0, (byte) 0x84, (byte) 0xfa, (byte) 0x29,
                (byte) 0x8b, (byte) 0x77, (byte) 0x93, (byte) 0xbd, (byte) 0x9d,
                (byte) 0xb6, (byte) 0x20, (byte) 0x05, (byte) 0x6f, (byte) 0xeb,
                (byte) 0xf4, (byte) 0x52, (byte) 0x17};

        byte[] macKey = {
                (byte) 0xc6, (byte) 0xc7, (byte) 0x7d, (byte) 0x6a, (byte) 0x73,
                (byte) 0xa3, (byte) 0x54, (byte) 0x33, (byte) 0x7a, (byte) 0x56,
                (byte) 0x43, (byte) 0x5e, (byte) 0x34, (byte) 0x60, (byte) 0x7d,
                (byte) 0xfe, (byte) 0x48, (byte) 0xe3, (byte) 0xac, (byte) 0xe1,
                (byte) 0x4e, (byte) 0x77, (byte) 0x31, (byte) 0x4d, (byte) 0xc6,
                (byte) 0xab, (byte) 0xc1, (byte) 0x72, (byte) 0xe7, (byte) 0xa7,
                (byte) 0x03, (byte) 0x0b};

        byte[] nextChainKey = {
                (byte) 0x28, (byte) 0xe8, (byte) 0xf8, (byte) 0xfe, (byte) 0xe5,
                (byte) 0x4b, (byte) 0x80, (byte) 0x1e, (byte) 0xef, (byte) 0x7c,
                (byte) 0x5c, (byte) 0xfb, (byte) 0x2f, (byte) 0x17, (byte) 0xf3,
                (byte) 0x2c, (byte) 0x7b, (byte) 0x33, (byte) 0x44, (byte) 0x85,
                (byte) 0xbb, (byte) 0xb7, (byte) 0x0f, (byte) 0xac, (byte) 0x6e,
                (byte) 0xc1, (byte) 0x03, (byte) 0x42, (byte) 0xa2, (byte) 0x46,
                (byte) 0xd1, (byte) 0x5d};

        ChainKey chainKey = new ChainKey(new HKDF(), seed, 0);

        assertTrue(Arrays.equals(chainKey.getKey(), seed));
        assertTrue(Arrays.equals(chainKey.getMessageKeys().getCipherKey().getEncoded(), messageKey));
        assertTrue(Arrays.equals(chainKey.getMessageKeys().getMacKey().getEncoded(), macKey));
        assertTrue(Arrays.equals(chainKey.getNextChainKey().getKey(), nextChainKey));
        assertTrue(chainKey.getIndex() == 0);
        assertTrue(chainKey.getMessageKeys().getCounter() == 0);
        assertTrue(chainKey.getNextChainKey().getIndex() == 1);
        assertTrue(chainKey.getNextChainKey().getMessageKeys().getCounter() == 1);
    }
}
