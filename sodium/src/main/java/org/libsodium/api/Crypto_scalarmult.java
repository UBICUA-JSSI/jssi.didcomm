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
import static org.libsodium.jni.SodiumConstants.CRYPTO_SCALARMULT_ED25519_SCALARBYTES;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_scalarmult {

    public static byte[] curve25519(byte[] sk, byte[] pk) throws SodiumException {
        byte[] agreement = new byte[CRYPTO_SCALARMULT_ED25519_SCALARBYTES];
        exception(Sodium.crypto_scalarmult_curve25519(agreement, sk, pk), "crypto_scalarmult_curve25519");
        return agreement;
    }

    public static byte[] curve25519_base(byte[] sk) throws SodiumException {
        byte[] base = new byte[CRYPTO_SCALARMULT_ED25519_SCALARBYTES];
        exception(Sodium.crypto_scalarmult_curve25519_base(base, sk), "crypto_scalarmult_curve25519_base");
        return base;
    }

}
