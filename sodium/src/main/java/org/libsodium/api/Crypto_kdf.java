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

import static org.libsodium.api.Crypto.exception;
import static org.libsodium.jni.SodiumConstants.*;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_kdf {

    public static byte[] kdf(int length, int id, byte[] context, byte[] master) throws SodiumException {
        byte[] subkey = new byte[length];
        exception(master.length - CRYPTO_KDF_KEYBYTES, "crypto_kdf_master_key_length_error");
        exception(context.length - CRYPTO_KDF_CONTEXTBYTES, "crypto_kdf_context_length_error");
        exception(Sodium.crypto_kdf_derive_from_key(subkey, length, id, context, master), "crypto_kdf_derive_from_key");
        return subkey;
    }

    public static byte[] kdf(int length, int id, byte[] master) throws SodiumException {
        byte[] subkey = new byte[length];
        byte[] context = "_UBICUA_".getBytes();
        exception(master.length - CRYPTO_KDF_KEYBYTES, "crypto_kdf_master_key_length_error");
        exception(Sodium.crypto_kdf_derive_from_key(subkey, length, id, context, master), "crypto_kdf_derive_from_key");
        return subkey;
    }

    public static byte[] kdf(int length, int id) throws SodiumException {
        byte[] master = new byte[CRYPTO_KDF_KEYBYTES];
        byte[] context = "_UBICUA_".getBytes();
        byte[] subkey = new byte[length];
        Sodium.crypto_kdf_keygen(master);
        exception(Sodium.crypto_kdf_derive_from_key(subkey, length, id, context, master), "crypto_kdf_derive_from_key");
        return subkey;
    }

}
