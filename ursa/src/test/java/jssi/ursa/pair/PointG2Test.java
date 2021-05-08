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

class PointG2Test {

    String data = "1 052DA02C48E7D4EF773EA47DF30FEB879D28ED3EA259B657A9713D09F33637FB 1 076DB5DC50643AC85A5867CC0BBEA8D1B0C0181902F7ED9E356F2E46F37F2493 1 0B0E88CB9F09987275EC5AF187269BA763B98A7C7C4BDFE2F419546BDCD9526E 1 07E87398A50B8318C0A2C9F446C9831AEFA86C04234675F796CE9EDEBF811C03 1 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8 1 0000000000000000000000000000000000000000000000000000000000000000";

    @Test
    void fromHex() {
        PointG2 point = PointG2.fromHex(data);
        assertEquals(data, point.toHex());
    }

    @Test
    void fromArray(){
        String data = "DABF1B89B584A1 6528C2CA3BB434 797565BB1CCB90 E63C6A6DC3C91A 24471A93 31D1B4E5C6F7E8 A4C48C9D1E4D0F BF10C3FBF53B80 27C94984204EFC 17DBA383 32F293DFC739DF 7E3DD3E71A4918 E2D84BF08244AE 3D7178DB477364 22738A3 3F9BCA3702EBD8 F8039636941D3C 1CE9B219CC559 9408F318813CCD 16C4CE4 FFFFFF7D07A8A8 FFFF7888802F07 FFC63D474548B7 F417D05FB10933 95E45DD 0 0 0 0 0";
        try {
            PointG2 pointG2 = PointG2.fromHex(data.split(" "));

            String xa = pointG2.point.getx().getA().toHex();
            String xb = pointG2.point.getx().getB().toHex();

            String ya = pointG2.point.gety().getA().toHex();
            String yb = pointG2.point.gety().getB().toHex();

            String za = pointG2.point.getz().getA().toHex();
            String zb = pointG2.point.getz().getB().toHex();

            StringBuffer buffer = new StringBuffer()
                    .append(xa).append(" ")
                    .append(xb).append(" ")
                    .append(ya).append(" ")
                    .append(yb).append(" ")
                    .append(za).append(" ")
                    .append(zb);

            assertEquals(buffer.toString(), data);
        } catch (CryptoException e){
            assertTrue(false, e.getMessage());
        }
    }

}