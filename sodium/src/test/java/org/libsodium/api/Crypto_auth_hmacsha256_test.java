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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.NavigableMap;

import static org.junit.jupiter.api.Assertions.*;

class Crypto_auth_hmacsha256_test {

    public Crypto_auth_hmacsha256_test(){
        NaCl.sodium();
    }

    @Test
    void verify() throws SodiumException {
        byte[] key = "0cd932d7ab20d568ee74ffa3f72aee35".getBytes();
        byte[] data = "080112586866694e597833537537745a6c326741726779646d51496878515a6b4e4958706a7a2b7135666c747a6a4b37664a304e6f6e6e5767366d704950313432634168396176734c42616d417a36785a44442b3559372b45513d3d12584570312b566d37576c394b476f37586250424d5353643661556334544d3942562b4a3941514248714b4537664431447837333961317a3968497537474255687a4c645565723152332f6451334e4e53766332485657673d3d".getBytes();
        byte[] hmac = Crypto_auth_hmacsha256.hmacsha256(data, key);
        assertTrue(Crypto_auth_hmacsha256.verify(hmac, data, key));

        byte[] result = hmacSha256(data, key);
        assertArrayEquals(result, hmac);
    }

    public static byte[] hmacSha256(byte[] data, byte[] key) {
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
        mac.update(data);
        return mac.doFinal();
    }

    @Test
    void update() throws NoSuchAlgorithmException, SodiumException, InvalidKeyException {

        byte[] key = "0cd932d7ab20d568ee74ffa3f72aee35".getBytes();
        byte[] data1 = "Hola caracola1".getBytes();
        byte[] data2 = "Hola caracola2".getBytes();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(data1);
        mac.update(data2);
        byte[] expected = mac.doFinal();

        byte[] state = Crypto_auth_hmacsha256.init(key);
        state = Crypto_auth_hmacsha256.update(state, data1);
        state = Crypto_auth_hmacsha256.update(state, data2);

        byte[] result = Crypto_auth_hmacsha256.finalize(state);
        assertArrayEquals(expected, result);
    }
}