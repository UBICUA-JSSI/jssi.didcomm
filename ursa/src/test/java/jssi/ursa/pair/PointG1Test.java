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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PointG1Test {

    @Test
    void fromHex() {
        String data = "1 03D433008A42E55FE3C6C4772D290EB3B0BF999F8281B4329E55033A32663625 1 0BDFD038889932B7C5CDD0BB846713710FBAB698201DFD4A380CDD1282E75060 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8";
        PointG1 point = PointG1.fromHex(data);
        assertEquals(data, point.toHex());
    }

    @Test
    void fromArray(){
        String data = "61FEBE2CFEAA04 5440090222C6AC E933B40264261C A5AA97421F4AEB 1D18E69F 23DDFBC92248BC F4CD0C7051CBEC 7057318CAFB551 B88E41A2CB508A 1461756F FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD";
        try {
            PointG1 pointG1 = PointG1.fromHex(data.split(" "));

            String x = pointG1.point.getx().redc().toHex();
            String y = pointG1.point.gety().redc().toHex();
            String z = pointG1.point.getz().redc().toHex();

            StringBuffer buffer = new StringBuffer()
                    .append(x).append(" ")
                    .append(y).append(" ")
                    .append(z);

            assertEquals(buffer.toString(), data);
        } catch (CryptoException e){
            assertTrue(false, e.getMessage());
        }
    }

}