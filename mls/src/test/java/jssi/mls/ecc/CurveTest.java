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

package jssi.mls.ecc;

import jssi.mls.InvalidKeyException;
import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertTrue;


public class CurveTest {

    public CurveTest() {
        NaCl.sodium();
    }

    @Test
    public void agreements_test() throws SodiumException, InvalidKeyException {
        for (int i = 0; i < 50; i++) {
            ECKeyPair alice = Curve.generateKeyPair();
            ECKeyPair bob = Curve.generateKeyPair();

            byte[] sharedAlice = Curve.calculateAgreement(bob.getPublicKey(), alice.getPrivateKey());
            byte[] sharedBob = Curve.calculateAgreement(alice.getPublicKey(), bob.getPrivateKey());

            assertTrue(Arrays.equals(sharedAlice, sharedBob));
        }
    }

    @Test
    public void signature_test() throws SodiumException, InvalidKeyException {

        ECKeyPair alice = Curve.generateKeyPair();

        byte[] data = {
                (byte) 0xed, (byte) 0xce, (byte) 0x9d, (byte) 0x9c, (byte) 0x41,
                (byte) 0x5c, (byte) 0xa7, (byte) 0x8c, (byte) 0xb7, (byte) 0x25,
                (byte) 0x2e, (byte) 0x72, (byte) 0xc2, (byte) 0xc4, (byte) 0xa5,
                (byte) 0x54, (byte) 0xd3, (byte) 0xeb, (byte) 0x29, (byte) 0x48,
                (byte) 0x5a, (byte) 0x0e, (byte) 0x1d, (byte) 0x50, (byte) 0x31,
                (byte) 0x18, (byte) 0xd1, (byte) 0xa8, (byte) 0x2d, (byte) 0x99,
                (byte) 0xfb, (byte) 0x4a};

        byte[] signature = Curve.calculateSignature(alice.getPrivateKey(), data);

        if (!Curve.verifySignature(alice.getPublicKey(), data, signature)) {
            throw new AssertionError("Sig verification failed!");
        }

    }
}
