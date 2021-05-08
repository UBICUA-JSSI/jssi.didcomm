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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_PUBLICKEYBYTES;

/**
 *
 * @author Andrei
 */
public class Crypto_sign_ed25519_test {
    
    public Crypto_sign_ed25519_test() {
        NaCl.sodium();
    }

    /**
     * Test of crypto_box_seal_open methods, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_sign_ed25519_sign_verify() throws SodiumException {
        
        Map<String, byte[]> result = Crypto_sign_ed25519.keypair();
        byte[] pk = result.get("pk");
        byte[] sk = result.get("sk");
        byte[] data = "Hola caracola".getBytes();
        
        byte[] sign = Crypto_sign_ed25519.sign(data, sk);
        boolean verified = Crypto_sign_ed25519.verify(data, sign, pk);
        assertTrue(verified);
    }
    
    /**
     * Test of crypto_box_seal_open methods, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_sign_ed25519_detached_verify() throws SodiumException {
        
        Map<String, byte[]> result = Crypto_sign_ed25519.keypair();
        byte[] pk = result.get("pk");
        byte[] sk = result.get("sk");
        byte[] data = "Hola caracola".getBytes();
        
        byte[] sign = Crypto_sign_ed25519.detached(data, sk);
        boolean verified = Crypto_sign_ed25519.verify_detached(data, sign, pk);
        assertTrue(verified);
    }

    @Test
    public void testCrypto_sign_ed25519_sk_to_pk() throws SodiumException {

        Map<String, byte[]> pair = Crypto_sign_ed25519.keypair();
        byte[] pk = pair.get("pk");
        byte[] sk = pair.get("sk");

        byte[] result = new byte[CRYPTO_SIGN_PUBLICKEYBYTES];
        System.arraycopy(sk, sk.length - result.length, result, 0, result.length);
        assertArrayEquals(result, pk);

        result = Crypto_sign_ed25519.sk_to_pk(sk);
        assertArrayEquals(result, pk);
    }
}
