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

import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPublicKey;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;
import jssi.mls.InvalidKeyException;
import jssi.mls.kdf.HKDF;
import jssi.mls.protocol.CiphertextMessage;
import jssi.mls.state.SessionState;
import jssi.mls.util.ByteUtil;
import jssi.mls.util.Pair;
import jssi.mls.util.guava.Optional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class RatchetingSession {

    public RatchetingSession() {

    }

    public static void initializeSession(SessionState sessionState, SymmetricProtocolParameters parameters)
            throws InvalidKeyException {
        if (isAlice(parameters.getOurBaseKey().getPublicKey(), parameters.getTheirBaseKey())) {
            AliceProtocolParameters.Builder aliceParameters = AliceProtocolParameters.newBuilder();

            aliceParameters.setOurBaseKey(parameters.getOurBaseKey())
                    .setOurIdentityKey(parameters.getOurIdentityKey())
                    .setTheirRatchetKey(parameters.getTheirRatchetKey())
                    .setTheirIdentityKey(parameters.getTheirIdentityKey())
                    .setTheirSignedPreKey(parameters.getTheirBaseKey())
                    .setTheirOneTimePreKey(Optional.absent());

            RatchetingSession.initializeSession(sessionState, aliceParameters.create());
        } else {
            BobProtocolParameters.Builder bobParameters = BobProtocolParameters.newBuilder();

            bobParameters.setOurIdentityKey(parameters.getOurIdentityKey())
                    .setOurRatchetKey(parameters.getOurRatchetKey())
                    .setOurSignedPreKey(parameters.getOurBaseKey())
                    .setOurOneTimePreKey(Optional.absent())
                    .setTheirBaseKey(parameters.getTheirBaseKey())
                    .setTheirIdentityKey(parameters.getTheirIdentityKey());

            RatchetingSession.initializeSession(sessionState, bobParameters.create());
        }
    }

    public static void initializeSession(SessionState sessionState, AliceProtocolParameters parameters)
            throws InvalidKeyException {
        NaCl.sodium();

        try {
            sessionState.setSessionVersion(CiphertextMessage.CURRENT_VERSION);
            sessionState.setRemoteIdentityKey(parameters.getTheirIdentityKey());
            sessionState.setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

            ECKeyPair sendingRatchetKey = Curve.generateKeyPair();
            ByteArrayOutputStream secrets = new ByteArrayOutputStream();

            secrets.write(getDiscontinuityBytes());

            secrets.write(Curve.calculateAgreement(parameters.getTheirSignedPreKey(),
                    parameters.getOurIdentityKey().getPrivateKey()));
            secrets.write(Curve.calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                    parameters.getOurBaseKey().getPrivateKey()));
            secrets.write(Curve.calculateAgreement(parameters.getTheirSignedPreKey(),
                    parameters.getOurBaseKey().getPrivateKey()));

            if (parameters.getTheirOneTimePreKey().isPresent()) {
                secrets.write(Curve.calculateAgreement(parameters.getTheirOneTimePreKey().get(),
                        parameters.getOurBaseKey().getPrivateKey()));
            }

            DerivedKeys derivedKeys = calculateDerivedKeys(secrets.toByteArray());
            Pair<RootKey, ChainKey> sendingChain = derivedKeys.getRootKey().createChain(parameters.getTheirRatchetKey(), sendingRatchetKey);

            sessionState.addReceiverChain(parameters.getTheirRatchetKey(), derivedKeys.getChainKey());
            sessionState.setSenderChain(sendingRatchetKey, sendingChain.second());
            sessionState.setRootKey(sendingChain.first());
        } catch (IOException | SodiumException e) {
            throw new AssertionError(e);
        }
    }

    public static void initializeSession(SessionState sessionState, BobProtocolParameters parameters)
            throws InvalidKeyException {

        try {
            sessionState.setSessionVersion(CiphertextMessage.CURRENT_VERSION);
            sessionState.setRemoteIdentityKey(parameters.getTheirIdentityKey());
            sessionState.setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

            ByteArrayOutputStream secrets = new ByteArrayOutputStream();

            secrets.write(getDiscontinuityBytes());

            secrets.write(Curve.calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                    parameters.getOurSignedPreKey().getPrivateKey()));
            secrets.write(Curve.calculateAgreement(parameters.getTheirBaseKey(),
                    parameters.getOurIdentityKey().getPrivateKey()));
            secrets.write(Curve.calculateAgreement(parameters.getTheirBaseKey(),
                    parameters.getOurSignedPreKey().getPrivateKey()));

            if (parameters.getOurOneTimePreKey().isPresent()) {
                secrets.write(Curve.calculateAgreement(parameters.getTheirBaseKey(),
                        parameters.getOurOneTimePreKey().get().getPrivateKey()));
            }

            DerivedKeys derivedKeys = calculateDerivedKeys(secrets.toByteArray());

            sessionState.setSenderChain(parameters.getOurRatchetKey(), derivedKeys.getChainKey());
            sessionState.setRootKey(derivedKeys.getRootKey());
        } catch (IOException | SodiumException e) {
            throw new AssertionError(e);
        }
    }

    private static byte[] getDiscontinuityBytes() {
        byte[] discontinuity = new byte[32];
        Arrays.fill(discontinuity, (byte) 0xFF);
        return discontinuity;
    }

    private static DerivedKeys calculateDerivedKeys(byte[] masterSecret) {
        HKDF kdf = new HKDF();
        byte[] derivedSecretBytes = kdf.deriveSecrets(masterSecret, "WhisperText".getBytes(), 64);
        byte[][] derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 32);

        return new DerivedKeys(new RootKey(kdf, derivedSecrets[0]), new ChainKey(kdf, derivedSecrets[1], 0));
    }

    private static boolean isAlice(ECPublicKey ourKey, ECPublicKey theirKey) {
        return ourKey.compareTo(theirKey) < 0;
    }

    private static class DerivedKeys {
        private final RootKey rootKey;
        private final ChainKey chainKey;

        private DerivedKeys(RootKey rootKey, ChainKey chainKey) {
            this.rootKey = rootKey;
            this.chainKey = chainKey;
        }

        public RootKey getRootKey() {
            return rootKey;
        }

        public ChainKey getChainKey() {
            return chainKey;
        }
    }
}
