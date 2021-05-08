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

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_version_test {
    
    public Crypto_version_test() {
        NaCl.sodium();
    }

    /**
     * Test of sodium_version_string method, of class Crypto_version.
     * @throws Exception
     */
    @Test
    public void sodium_version_string() throws Exception {
        String version = Crypto_version.version();
        assertNotNull(version);
    }
}
