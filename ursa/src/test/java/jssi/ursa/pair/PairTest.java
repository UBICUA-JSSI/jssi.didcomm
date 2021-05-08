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

import static org.junit.jupiter.api.Assertions.*;

class PairTest {

    @Test
    void pairing_definition_bilinearity() {
        GroupOrderElement a = new GroupOrderElement();
        GroupOrderElement b = new GroupOrderElement();
        PointG1 p = new PointG1();
        PointG2 q = new PointG2();

        Pair left = Pair.pair(p.mul(a), q.mul(b));
        Pair right = Pair.pair(p, q).pow(a.mulmod(b));
        assertArrayEquals(left.toBytes(), right.toBytes());
    }

    @Test
    void point_g1_infinity_test() {
        PointG1 p = new PointG1().infinity();
        PointG1 q = new PointG1();
        PointG1 result = p.add(q);
        assertArrayEquals(q.toBytes(), result.toBytes());
    }

    @Test
    void point_g1_infinity_test2() {
        PointG1 p = new PointG1();
        PointG1 inf = p.sub(p);
        PointG1 q =new PointG1();
        PointG1 result = inf.add(q);
        assertArrayEquals(q.toBytes(), result.toBytes());
    }

    @Test
    void point_g2_infinity_test() {
        PointG2 p = new PointG2().infinity();
        PointG2 q = new PointG2();
        PointG2 result = p.add(q);
        assertArrayEquals(q.toBytes(), result.toBytes());
    }

    @Test
    void inverse_for_pairing() {
        PointG1 p1 = new PointG1();
        PointG2 q1 = new PointG2();
        PointG1 p2 = new PointG1();
        PointG2 q2 = new PointG2();
        Pair pair1 = Pair.pair(p1, q1);
        Pair pair2 = Pair.pair(p2, q2);
        Pair pair_result = pair1.mul(pair2);
        Pair pair3 = pair_result.mul(pair1.inverse());
        assertEquals(pair2, pair3);
    }

    @Test
    void fromHex(){
        String data = "BAF4F6C1044467 B355263E5FED41 8C0AF4C3EB94AF 3DE0C83ACA9928 2D6A7C6 FDF167021A1737 F7663EE5B2767B C5C4D3E69D387 34AA472296FCC7 B1660F7 C4741C69824558 CE22B92C952568 BB8179722E1BE7 1036505FEC026E 1C07F9FD DEAB5ECFD267CE 2E372388203E8D 973CB3DFAED87A EAB1BCFACB147E 12AC5746 BA65AD126B3FA5 1E1CF9FFC748E9 6017A982889E18 7AC0602B49C5E4 BAF574F 6CF7E2221ABC1 C4ABDFD08A7CD4 5CF4AB327CE15 3135590EE8EFC4 8192962 4FFCD9C89ABC45 3E0764B6CD0CF7 228E1021AA539B 8BA7447BCE3D7F F203473 DFB3E31073CDBD 7924EAC9D036C1 716066DCE76DC9 87B72FD4831A7 7296BA1 F417B8E0DAA939 9CA99939CB747E C79AC00D77664D D5C8F4836CDC28 1C615963 FD093CEBD6DED8 D16D939D4144E6 D209EEB27A2D40 E10AC83BFD60E4 4221B1A 535859DCF661A3 4A2F9EA4995F28 F9E4ECB0F4A21F CCB9D054387AF6 1B0A327E 20BF74410EF2D0 878F7EC03EA36B 76029AEF058F80 D988F4E307EC0E B9001C";
        String[] hex = data.split(" ");
        Pair pair = null;
        try {
            pair = Pair.fromHex(hex);
        } catch (CryptoException e){
            assertTrue(false, e.getMessage());
        }
      assertNotNull(pair);
    }

    @Test
    void toHex(){
        String data = "BAF4F6C1044467 B355263E5FED41 8C0AF4C3EB94AF 3DE0C83ACA9928 2D6A7C6 FDF167021A1737 F7663EE5B2767B C5C4D3E69D387 34AA472296FCC7 B1660F7 C4741C69824558 CE22B92C952568 BB8179722E1BE7 1036505FEC026E 1C07F9FD DEAB5ECFD267CE 2E372388203E8D 973CB3DFAED87A EAB1BCFACB147E 12AC5746 BA65AD126B3FA5 1E1CF9FFC748E9 6017A982889E18 7AC0602B49C5E4 BAF574F 6CF7E2221ABC1 C4ABDFD08A7CD4 5CF4AB327CE15 3135590EE8EFC4 8192962 4FFCD9C89ABC45 3E0764B6CD0CF7 228E1021AA539B 8BA7447BCE3D7F F203473 DFB3E31073CDBD 7924EAC9D036C1 716066DCE76DC9 87B72FD4831A7 7296BA1 F417B8E0DAA939 9CA99939CB747E C79AC00D77664D D5C8F4836CDC28 1C615963 FD093CEBD6DED8 D16D939D4144E6 D209EEB27A2D40 E10AC83BFD60E4 4221B1A 535859DCF661A3 4A2F9EA4995F28 F9E4ECB0F4A21F CCB9D054387AF6 1B0A327E 20BF74410EF2D0 878F7EC03EA36B 76029AEF058F80 D988F4E307EC0E B9001C";
        String[] hex = data.split(" ");
        Pair pair = null;
        try {
            pair = Pair.fromHex(hex);
        } catch (CryptoException e){
            assertTrue(false, e.getMessage());
        }
        String result = pair.toHex();
        assertEquals(result, data);
    }
}