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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.libsodium.jni.SodiumConstants.*;

public class Crypto_auth_test {
    
    public Crypto_auth_test() {
        NaCl.sodium();
    }
    
    /**
     * Test of crypto_auth_encrypt_authenticate_verify method, of class Crypto_auth.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_auth_encrypt_authenticate_verify() throws SodiumException {
        
        byte[] key = Crypto_auth.keygen();
        byte[] data = "Hola caracola".getBytes();
        byte[] cipher = Crypto_auth.authenticate(data, key);
        boolean result = Crypto_auth.verify(cipher, data, key);
        assertTrue(result);
    }

    @Test
    public void testCrypto_auth_hmacsha256_verify() throws SodiumException {

        byte[] key = new byte[CRYPTO_AUTH_KEYBYTES];
        byte[] data = "Hola caracola".getBytes();
        byte[] cipher = Crypto_auth.hmacsha256(data, key);
        boolean result = Crypto_auth.hmacsha256_verify(cipher, data, key);
        assertTrue(result);
    }

    @Test
    public void testCrypto_auth_hmacsha256_multipart_verify() throws SodiumException {

        byte[] key = new byte[CRYPTO_AUTH_HMACSHA256_KEYBYTES];

        byte[] data1 = "Arbitrary data to hash".getBytes();
        byte[] data2 = " is longer than expected".getBytes();
        byte[] append = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, append, 0, data1.length);
        System.arraycopy(data2, 0, append, data1.length, data2.length);

        byte[] state = Crypto_auth.hmacsha256_init(key);
        Crypto_auth.hmacsha256_update(state, data1);
        Crypto_auth.hmacsha256_update(state, data2);
        byte[] cipher = Crypto_auth.hmacsha256_final(state);
        boolean result = Crypto_auth.hmacsha256_verify(cipher, append, key);
        assertTrue(result);
    }
    
}
