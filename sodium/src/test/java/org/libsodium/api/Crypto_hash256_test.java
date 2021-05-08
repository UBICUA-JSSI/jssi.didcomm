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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class Crypto_hash256_test {

    public Crypto_hash256_test(){
        NaCl.sodium();
    }

    @Test
    void digest() throws NoSuchAlgorithmException, SodiumException {

        byte[] data = "Hola caracola".getBytes();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data);
        byte[] expected = md.digest();
        byte[] result = Crypto_hash256.digest(data);
        assertArrayEquals(expected, result);
    }

    @Test
    void update() throws NoSuchAlgorithmException, SodiumException {

        byte[] data1 = "Hola caracola1".getBytes();
        byte[] data2 = "Hola caracola2".getBytes();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data1);
        md.update(data2);
        byte[] expected = md.digest();

        byte[] state = Crypto_hash256.init();
        state = Crypto_hash256.update(state, data1);
        state = Crypto_hash256.update(state, data2);

        byte[] result = Crypto_hash256.finalize(state);
        assertArrayEquals(expected, result);
    }
}