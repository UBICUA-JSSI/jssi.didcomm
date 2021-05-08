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

import static org.junit.jupiter.api.Assertions.*;

class Crypto_kdf_test {

    public Crypto_kdf_test(){
        NaCl.sodium();
    }

    @Test
    void kdf() throws SodiumException {
        int expected = 16;
        byte[] result = Crypto_kdf.kdf(expected, 1);
        assertEquals(result.length, expected);
    }
}