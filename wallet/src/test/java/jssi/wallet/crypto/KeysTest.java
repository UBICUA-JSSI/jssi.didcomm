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

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.libsodium.api.Crypto_randombytes;
import org.libsodium.jni.NaCl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
 */
public class KeysTest {
    
     private Keys instance;
    
    public KeysTest() throws SodiumException {
        NaCl.sodium();
        instance = new Keys().init();
    }
    


   /**
     * Test of serializeEncrypted method, of class Keys.
     * @throws SodiumException
     * @throws IOException
     */
    @Test
    public void testSerialize() throws SodiumException, IOException  {
        byte[] master_key = new byte[CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES];
        Crypto_randombytes.buf(master_key);
        byte[] expected;
        byte[] result = instance.serialize(master_key);
        
        
        expected = instance.deserialize(result, master_key).getTypeKey();
        assertArrayEquals(expected, instance.getTypeKey());
        expected = instance.deserialize(result, master_key).getNameKey();
        assertArrayEquals(expected, instance.getNameKey());
        expected = instance.deserialize(result, master_key).getValueKey();
        assertArrayEquals(expected, instance.getValueKey());
        expected = instance.deserialize(result, master_key).getItemHmacKey();
        assertArrayEquals(expected, instance.getItemHmacKey());
        expected = instance.deserialize(result, master_key).getTagNameKey();
        assertArrayEquals(expected, instance.getTagNameKey());
        expected = instance.deserialize(result, master_key).getTagValueKey();
        assertArrayEquals(expected, instance.getTagValueKey());
        expected = instance.deserialize(result, master_key).getTagsHmacKey();
        assertArrayEquals(expected, instance.getTagsHmacKey());
    }

}
