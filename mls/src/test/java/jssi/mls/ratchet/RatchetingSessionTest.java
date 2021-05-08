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

package jssi.mls.ratchet;

import org.junit.jupiter.api.Test;

import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;
import jssi.mls.IdentityKey;
import jssi.mls.IdentityKeyPair;
import jssi.mls.InvalidKeyException;
import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPrivateKey;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.state.SessionState;
import jssi.mls.util.guava.Optional;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RatchetingSessionTest {

    public RatchetingSessionTest(){
        NaCl.sodium();
    }

    @Test
    public void ratchetingSession_test() throws InvalidKeyException, SodiumException {

        ECKeyPair bobKeyPair = Curve.generateKeyPair();
        ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
        ECKeyPair bobSignedPreKeyPair = Curve.generateKeyPair();


        ECKeyPair aliceKeyPair = Curve.generateKeyPair();
        ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();

        BobProtocolParameters bobParameters = BobProtocolParameters.newBuilder()
                .setOurIdentityKey(new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()), bobIdentityKeyPair.getPrivateKey()))
                .setOurSignedPreKey(bobSignedPreKeyPair)
                .setOurRatchetKey(bobKeyPair)
                .setOurOneTimePreKey(Optional.<ECKeyPair>absent())
                .setTheirIdentityKey(new IdentityKey(aliceIdentityKeyPair.getPublicKey()))
                .setTheirBaseKey(aliceKeyPair.getPublicKey())
                .create();

        SessionState bobSession = new SessionState();
        RatchetingSession.initializeSession(bobSession, bobParameters);

        assertTrue(bobSession.getLocalIdentityKey().equals(new IdentityKey(bobIdentityKeyPair.getPublicKey())));
        assertTrue(bobSession.getRemoteIdentityKey().equals(new IdentityKey(aliceIdentityKeyPair.getPublicKey())));

        AliceProtocolParameters aliceParameters = AliceProtocolParameters.newBuilder()
                .setOurBaseKey(aliceKeyPair)
                .setOurIdentityKey(new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()), aliceIdentityKeyPair.getPrivateKey()))
                .setTheirIdentityKey(new IdentityKey(bobIdentityKeyPair.getPublicKey()))
                .setTheirSignedPreKey(bobSignedPreKeyPair.getPublicKey())
                .setTheirRatchetKey(bobKeyPair.getPublicKey())
                .setTheirOneTimePreKey(Optional.<ECPublicKey>absent())
                .create();

        SessionState aliceSession = new SessionState();
        RatchetingSession.initializeSession(aliceSession, aliceParameters);

        assertTrue(aliceSession.getLocalIdentityKey().equals(new IdentityKey(aliceIdentityKeyPair.getPublicKey())));
        assertTrue(aliceSession.getRemoteIdentityKey().equals(new IdentityKey(bobIdentityKeyPair.getPublicKey())));

        assertArrayEquals(aliceSession.getReceiverChainKey(bobKeyPair.getPublicKey()).getKey(), bobSession.getSenderChainKey().getKey());

    }

}
