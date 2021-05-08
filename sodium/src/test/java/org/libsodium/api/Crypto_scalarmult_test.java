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

import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class Crypto_scalarmult_test {

    public Crypto_scalarmult_test() {
        NaCl.sodium();
    }

    @Test
    void curve25519() throws SodiumException {
        Map<String, byte[]> result = Crypto_sign_ed25519.keypair();
        byte[] skClient = result.get("sk");

        Map<String, byte[]> result1 = Crypto_sign_ed25519.keypair();
        byte[] skServer = result1.get("sk");

        byte[] pkClient = Crypto_scalarmult.curve25519_base(skClient);
        byte[] sharedServer = Crypto_scalarmult.curve25519(skServer, pkClient);

        byte[] pkServer = Crypto_scalarmult.curve25519_base(skServer);
        byte[] sharedClient = Crypto_scalarmult.curve25519(skClient, pkServer);
        assertArrayEquals(sharedClient, sharedServer);

    }


}