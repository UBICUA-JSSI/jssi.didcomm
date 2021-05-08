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
package jssi.wallet.crypto;

import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
 */
public class KeyDerivationDataTest {
    
    public KeyDerivationDataTest() {
        NaCl.sodium();
    }

     /**
     * Test of deriveMasterKey method, of class KeyDerivationData.
     * @throws SodiumException
     */
    @Test
    public void testDeriveRawMasterKey() throws SodiumException {
        KeyDerivationData instance = new KeyDerivationData("8dvfYSt5d1taSd6yJdpjq4emkwsPDDLYxkNFysFD2cZY", Method.RAW);
        int expResult = CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
        byte[] result = instance.deriveMasterKey();
        assertEquals(expResult, result.length);
    }
    
    @Test
    public void testDeriveArgon2i_ModMasterKey() throws SodiumException {
        
        byte[] salt = new byte[]{
            (byte)24, (byte)62, (byte)35, (byte)31, (byte)123, (byte)241, (byte)94, (byte)24, 
            (byte)192, (byte)110, (byte)199, (byte)143, (byte)173, (byte)20, (byte)23, (byte)102,
            (byte)184, (byte)99, (byte)221, (byte)64, (byte)247, (byte)230, (byte)11, (byte)253, 
            (byte)10, (byte)7, (byte)80, (byte)236, (byte)185, (byte)249, (byte)110, (byte)187
        };
        byte[] expected = new byte[]{
            (byte)148, (byte)89, (byte)76, (byte)239, (byte)127, (byte)103, (byte)13, (byte)86, 
            (byte)84, (byte)217, (byte)216, (byte)13, (byte)223, (byte)141, (byte)225, (byte)41,
            (byte)223, (byte)126, (byte)145, (byte)138, (byte)174, (byte)31, (byte)142, (byte)199,
            (byte)81, (byte)12, (byte)40, (byte)201, (byte)67, (byte)8, (byte)6, (byte)251
        };
        
        KeyDerivationData instance = new KeyDerivationData("passphrase", salt, Method.ARGON2I_MOD);
        byte[] result = instance.deriveMasterKey();
        assertArrayEquals(expected, result);
    }
    
    @Test
    public void testDeriveArgon2i_IntMasterKey() throws SodiumException {
        
        byte[] salt = new byte[]{
            (byte)24, (byte)62, (byte)35, (byte)31, (byte)123, (byte)241, (byte)94, (byte)24, 
            (byte)192, (byte)110, (byte)199, (byte)143, (byte)173, (byte)20, (byte)23, (byte)102,
            (byte)184, (byte)99, (byte)221, (byte)64, (byte)247, (byte)230, (byte)11, (byte)253, 
            (byte)10, (byte)7, (byte)80, (byte)236, (byte)185, (byte)249, (byte)110, (byte)187
        };
        byte[] expected = new byte[]{
            (byte)247, (byte)55, (byte)177, (byte)252, (byte)244, (byte)130, (byte)218, (byte)129, 
            (byte)113, (byte)206, (byte)72, (byte)44, (byte)29, (byte)68, (byte)134, (byte)215,
            (byte)249, (byte)233, (byte)131, (byte)199, (byte)38, (byte)87, (byte)69, (byte)217, 
            (byte)156, (byte)217, (byte)10, (byte)160, (byte)30, (byte)148, (byte)80, (byte)160
        };
        
        KeyDerivationData instance = new KeyDerivationData("passphrase", salt, Method.ARGON2I_INT);
        byte[] result = instance.deriveMasterKey();
        assertArrayEquals(expected, result);
    }
}
