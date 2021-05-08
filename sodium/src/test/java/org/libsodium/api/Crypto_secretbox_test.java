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
package org.libsodium.api;

import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SECRETBOX_NONCEBYTES;

public class Crypto_secretbox_test {
    
    public Crypto_secretbox_test() {
        NaCl.sodium();
    }
    

    /**
     * Test of crypto_secretbox_easy_open methods, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_secretbox_easy_open() throws SodiumException {
        
        byte[] nonce = new byte[CRYPTO_SECRETBOX_NONCEBYTES];
        Crypto_randombytes.buf(nonce);
        byte[] key = Crypto_secretbox.keygen();
        byte[] data = "Hola caracola".getBytes();

        byte[] cipher = Crypto_secretbox.easy(data, nonce, key);
        byte[] result = Crypto_secretbox.open_easy(cipher, nonce, key);
        assertArrayEquals(data, result);
    }
        
   
    
}
