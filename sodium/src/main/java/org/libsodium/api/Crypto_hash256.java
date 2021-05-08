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

import java.util.Arrays;

import static org.libsodium.jni.SodiumConstants.CRYPTO_HASH_SHA256_BYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_HASH_SHA256_STATE;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_hash256 extends Crypto {

    public static byte[] init() throws SodiumException {

        byte[] state = new byte[CRYPTO_HASH_SHA256_STATE];
        exception(Sodium.crypto_hash_sha256_init(state), "crypto_hash_sha256_init");
        return state;
    }

    public static byte[] update(byte[] state, byte[] data) throws SodiumException {
        exception(Sodium.crypto_hash_sha256_update(state, data, data.length), "crypto_hash_sha256_update");
        return state;
    }

    public static byte[] finalize(byte[] state) throws SodiumException {
        byte[] hash = new byte[CRYPTO_HASH_SHA256_BYTES];
        exception(Sodium.crypto_hash_sha256_final(state, hash), "crypto_hash_sha256_final");
        return hash;
    }

    public static byte[] digest(byte[] data) throws SodiumException {
        byte[] hash = new byte[CRYPTO_HASH_SHA256_BYTES];
        exception(Sodium.crypto_hash_sha256(hash, data, data.length), "crypto_hash_sha256");
        return hash;
    }

}
