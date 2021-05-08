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
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_aead_chacha20poly1305_test {
    
    public Crypto_aead_chacha20poly1305_test() {
        NaCl.sodium();
    }
    


    /**
     * Test of crypto_aead_chacha20poly1305_encrypt_decrypt method, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_aead_chacha20poly1305_encrypt_decrypt() throws SodiumException {
        
        byte[] nonce = new byte[CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES];
        Crypto_randombytes.buf(nonce);
        byte[] key = Crypto_aead_chacha20poly1305.keygen();
        byte[] data = "Hola caracola".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();
        
        byte[] cipher = Crypto_aead_chacha20poly1305.encrypt(data, add, nonce, key);
        byte[] result = Crypto_aead_chacha20poly1305.decrypt(cipher, add, nonce, key);
        assertArrayEquals(data, result);
    }
    
    /**
     * Test of crypto_aead_chacha20poly1305_encrypt_decrypt_detached method, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_aead_chacha20poly1305_encrypt_decrypt_detached() throws SodiumException {
        
        byte[] nonce = new byte[CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES];
        Crypto_randombytes.buf(nonce);
        byte[] key = Crypto_aead_chacha20poly1305.keygen();
        byte[] data = "Hola caracola".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();
        
        Map<String, byte[]> result = Crypto_aead_chacha20poly1305.encrypt_detached(data, add, nonce, key);
        byte[] tag = result.get("tag");
        byte[] cipher = result.get("cipher");
        byte[] decrypted = Crypto_aead_chacha20poly1305.decrypt_detached(cipher, tag, add, nonce, key);
        assertArrayEquals(data, decrypted);
    }
}
