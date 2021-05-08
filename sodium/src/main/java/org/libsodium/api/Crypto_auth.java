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

import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumException;

import static org.libsodium.jni.SodiumConstants.*;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_auth extends Crypto{

    public static byte[] authenticate(byte[] data, byte[] key) throws SodiumException {
        byte[] cipher = new byte[CRYPTO_AUTH_BYTES];
        exception(Sodium.crypto_auth(cipher, data, data.length, key), "crypto_auth");
        return cipher;
    }
    
    public static boolean verify(byte[] cipher, byte[] data, byte[] key) throws SodiumException {
        exception(Sodium.crypto_auth_verify(cipher, data, data.length, key), "crypto_auth_verify");
        return true;
    }
   
    public static byte[] keygen() throws SodiumException {
        // FIXME: crypto_auth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] key = new byte[CRYPTO_AUTH_KEYBYTES];
        Crypto_randombytes.buf(key);
        return key;
    }

    public static byte[] hmacsha256(byte[] message, byte[] key) throws SodiumException {
        byte[] cipher = new byte[CRYPTO_AUTH_HMACSHA256_BYTES];
        exception(Sodium.crypto_auth_hmacsha256(cipher, message, message.length, key), "crypto_auth_hmacsha256");
        return cipher;
    }

    public static byte[] hmacsha256_init(byte[] key) throws SodiumException {
        byte[] state = new byte[CRYPTO_AUTH_HMACSHA256_STATEBYTES];
        exception(Sodium.crypto_auth_hmacsha256_init(state, key, key.length), "crypto_auth_hmacsha256_init");
        return state;
    }

    public static boolean hmacsha256_update(byte[] state, byte[] data) throws SodiumException {
        exception(Sodium.crypto_auth_hmacsha256_update(state, data, data.length), "crypto_auth_hmacsha256_update");
        return true;
    }

    public static byte[] hmacsha256_final(byte[] state) throws SodiumException {
        byte[] cipher = new byte[CRYPTO_AUTH_HMACSHA256_BYTES];
        exception(Sodium.crypto_auth_hmacsha256_final(state, cipher), "crypto_auth_hmacsha256_final");
        return cipher;
    }

    public static boolean hmacsha256_verify(byte[] cipher, byte[] data, byte[] key) throws SodiumException {
        exception(Sodium.crypto_auth_hmacsha256_verify(cipher, data, data.length, key), "crypto_auth_hmacsha256_verify");
        return true;
    }
}
