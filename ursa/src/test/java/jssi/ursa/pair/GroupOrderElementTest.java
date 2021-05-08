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

package jssi.ursa.pair;

import org.junit.jupiter.api.Test;
import jssi.ursa.util.Bytes;

import static org.junit.jupiter.api.Assertions.*;

class GroupOrderElementTest {

    @Test
    void fromBytes() throws CryptoException {
        byte[] vec = new byte[]{
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                (byte) 116, (byte) 221, (byte) 243, (byte) 243, (byte) 0, (byte) 77, (byte) 170, (byte) 65,
                (byte) 179, (byte) 245, (byte) 119, (byte) 182, (byte) 251, (byte) 185, (byte) 78, (byte) 98};

        GroupOrderElement bytes = GroupOrderElement.fromBytes(vec);
        byte[] result = bytes.toBytes();
        assertArrayEquals(vec, result);
    }

    @Test
    void toBytes() throws CryptoException {
        GroupOrderElement goe = new GroupOrderElement();
        byte[] bytes = goe.toBytes();
        byte[] result =  GroupOrderElement.fromHex(Bytes.toHex(bytes)).toBytes();
        assertArrayEquals(bytes, result);
    }

    @Test
    void toHex(){
        String data = "9A7934671787E7 B44902FD431283 E541AB2729B4F7 E4BDDF7F08FE77 19ADFD0";
        try {
            GroupOrderElement goe = GroupOrderElement.fromHex(data.split(" "));
            assertEquals(goe.toHex(), data);
            assertEquals(goe.toBytes().length, GroupOrderElement.BYTES_REPR_SIZE);
        } catch (CryptoException e){
            assertTrue(false, e.getMessage());
        }
    }

    @Test
    void inverse() throws CryptoException {
        GroupOrderElement goe = new GroupOrderElement();
        GroupOrderElement inverse = goe.inverse();
        GroupOrderElement result = inverse.inverse();
        assertArrayEquals(goe.toBytes(), result.toBytes());
    }

    @Test
    void modneg() {
        GroupOrderElement goe = new GroupOrderElement();
        GroupOrderElement modneg = goe.modneg();
        GroupOrderElement result = modneg.modneg();
        assertArrayEquals(goe.toBytes(), result.toBytes());
    }
}