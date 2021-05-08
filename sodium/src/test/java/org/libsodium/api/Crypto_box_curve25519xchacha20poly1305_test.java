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

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class Crypto_box_curve25519xchacha20poly1305_test {
    
    public Crypto_box_curve25519xchacha20poly1305_test() {
        NaCl.sodium();
    }
    
    /**
     * Test of crypto_box_curve25519xchacha20poly1305_seal_open methods, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_box_curve25519xchacha20poly1305_seal_open() throws SodiumException {
        
        Map<String, byte[]> result = Crypto_box_curve25519xchacha20poly1305.keypair();
        byte[] pk = result.get("pk");
        byte[] sk = result.get("sk");
        byte[] data = "Hola caracola".getBytes();
        
        byte[] cipher = Crypto_box_curve25519xchacha20poly1305.seal(data, pk);
        byte[] opened = Crypto_box_curve25519xchacha20poly1305.seal_open(cipher, pk, sk);
        assertArrayEquals(data, opened);
    }
        
   
    
}
