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

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NONCEBYTES;

public class Crypto_aead_xchacha20poly1305_ietf_test {
    
    public Crypto_aead_xchacha20poly1305_ietf_test() {
        NaCl.sodium();
    }
    

    /**
     * Test of crypto_aead_xchacha20poly1305_ietf_encrypt_decrypt_detached method, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_aead_xchacha20poly1305_ietf_encrypt_decrypt_detached() throws SodiumException {
        
        byte[] nonce = new byte[CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NONCEBYTES];
        Crypto_randombytes.buf(nonce);
        byte[] key = Crypto_aead_xchacha20poly1305_ietf.keygen();
        byte[] data = "Hola caracola".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        Map<String, byte[]> result = Crypto_aead_xchacha20poly1305_ietf.encrypt_detached(data, add, nonce, key);
        
        byte[] cipher = result.get("cipher");
        byte[] tag = result.get("tag");

        byte[] decrypted = Crypto_aead_xchacha20poly1305_ietf.decrypt_detached(cipher, tag, add, nonce, key);
        assertArrayEquals(data, decrypted);
    }
        
    
    /**
     * Test of crypto_aead_xchacha20poly1305_encrypt_decrypt method, of class SodiumAPI.
     */
    @Test
    public void testCrypto_aead_xchacha20poly1305_ietf_encrypt_decrypt() throws Exception {
        
        byte[] nonce = new byte[CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NONCEBYTES];
        Crypto_randombytes.buf(nonce);
        byte[] key = Crypto_aead_xchacha20poly1305_ietf.keygen();
        byte[] data = "Hola caracola".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();
        
        byte[] cipher = Crypto_aead_xchacha20poly1305_ietf.encrypt(data, add, nonce, key);
        byte[] decrypted = Crypto_aead_xchacha20poly1305_ietf.decrypt(cipher, add, nonce, key);
        assertArrayEquals(data, decrypted);
    }
    
}
