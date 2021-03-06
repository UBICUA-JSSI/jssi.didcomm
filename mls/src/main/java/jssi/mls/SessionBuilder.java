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
package jssi.mls;


import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.state.*;
import org.libsodium.jni.SodiumException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.mls.protocol.PreKeyMessage;
import jssi.mls.protocol.Message;
import jssi.mls.ratchet.AliceProtocolParameters;
import jssi.mls.ratchet.BobProtocolParameters;
import jssi.mls.ratchet.RatchetingSession;
import jssi.mls.util.guava.Optional;

/**
 * SessionBuilder is responsible for setting up encrypted sessions.
 * Once a session has been established, {@link SessionCipher}
 * can be used to encrypt/decrypt messages in that session.
 * <p>
 * Sessions are built from one of three different possible vectors:
 * <ol>
 *   <li>A {@link PreKeyBundle} retrieved from a server.</li>
 *   <li>A {@link PreKeyMessage} received from a client.</li>
 * </ol>
 * <p>
 * Sessions are constructed per recipientId + deviceId tuple.  Remote logical users are identified
 * by their recipientId, and each logical recipientId can have multiple physical devices.
 *
 * @author Moxie Marlinspike
 */
public class SessionBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(SessionBuilder.class);

    private static final String TAG = SessionBuilder.class.getSimpleName();

    private final SessionStore sessionStore;
    private final PreKeyStore preKeyStore;
    private final SignedPreKeyStore signedPreKeyStore;
    private final IdentityKeyStore identityKeyStore;
    private final ProtocolAddress remoteAddress;

    /**
     * Constructs a SessionBuilder.
     *
     * @param sessionStore     The {@link SessionStore} to store the constructed session in.
     * @param preKeyStore      The {@link  PreKeyStore} where the client's local {@link PreKeyRecord}s are stored.
     * @param identityKeyStore The {@link IdentityKeyStore} containing the client's identity key information.
     * @param remoteAddress    The address of the remote user to build a session with.
     */
    public SessionBuilder(SessionStore sessionStore,
                          PreKeyStore preKeyStore,
                          SignedPreKeyStore signedPreKeyStore,
                          IdentityKeyStore identityKeyStore,
                          ProtocolAddress remoteAddress) {
        this.sessionStore = sessionStore;
        this.preKeyStore = preKeyStore;
        this.signedPreKeyStore = signedPreKeyStore;
        this.identityKeyStore = identityKeyStore;
        this.remoteAddress = remoteAddress;
    }

    /**
     * Constructs a SessionBuilder
     *
     * @param store         The {@link ProtocolStore} to store all state information in.
     * @param remoteAddress The address of the remote user to build a session with.
     */
    public SessionBuilder(ProtocolStore store, ProtocolAddress remoteAddress) {
        this(store, store, store, store, remoteAddress);
    }

    /**
     * Build a new session from a received {@link PreKeyMessage}.
     * <p>
     * After a session is constructed in this way, the embedded {@link Message}
     * can be decrypted.
     *
     * @param message The received {@link PreKeyMessage}.
     * @throws InvalidKeyIdException      when there is no local
     *                                    {@link PreKeyRecord}
     *                                    that corresponds to the PreKey ID in
     *                                    the message.
     * @throws InvalidKeyException        when the message is formatted incorrectly.
     * @throws UntrustedIdentityException when the {@link IdentityKey} of the sender is untrusted.
     */
    Optional<Integer> process(SessionRecord sessionRecord, PreKeyMessage message)
            throws InvalidKeyIdException, InvalidKeyException, UntrustedIdentityException {
        IdentityKey theirIdentityKey = message.getIdentityKey();

        if (!identityKeyStore.isTrustedIdentity(remoteAddress, theirIdentityKey, IdentityKeyStore.Direction.RECEIVING)) {
            throw new UntrustedIdentityException(remoteAddress.getDid(), theirIdentityKey);
        }

        Optional<Integer> unsignedPreKeyId = processV3(sessionRecord, message);

        identityKeyStore.saveIdentity(remoteAddress, theirIdentityKey);

        return unsignedPreKeyId;
    }

    private Optional<Integer> processV3(SessionRecord sessionRecord, PreKeyMessage message)
            throws InvalidKeyIdException, InvalidKeyException {

        if (sessionRecord.hasSessionState(message.getMessageVersion(), message.getBaseKey().getBytes())) {
            LOG.warn(TAG, "We've already setup a session for this V3 message, letting bundled message fall through...");
            return Optional.absent();
        }

        ECKeyPair ourSignedPreKey = signedPreKeyStore.loadSignedPreKey(message.getSignedPreKeyId()).getKeyPair();

        BobProtocolParameters.Builder parameters = BobProtocolParameters.newBuilder();

        parameters.setTheirBaseKey(message.getBaseKey())
                .setTheirIdentityKey(message.getIdentityKey())
                .setOurIdentityKey(identityKeyStore.getIdentityKeyPair())
                .setOurSignedPreKey(ourSignedPreKey)
                .setOurRatchetKey(ourSignedPreKey);

        if (message.getPreKeyId().isPresent()) {
            parameters.setOurOneTimePreKey(Optional.of(preKeyStore.loadPreKey(message.getPreKeyId().get()).getKeyPair()));
        } else {
            parameters.setOurOneTimePreKey(Optional.absent());
        }

        if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

        RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

        sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.getLocalRegistrationId());
        sessionRecord.getSessionState().setRemoteRegistrationId(message.getRegistrationId());
        sessionRecord.getSessionState().setAliceBaseKey(message.getBaseKey().getBytes());

        if (message.getPreKeyId().isPresent()) {
            return message.getPreKeyId();
        } else {
            return Optional.absent();
        }
    }

    /**
     * Build a new session from a {@link PreKeyBundle} retrieved from
     * a server.
     *
     * @param preKey A PreKey for the destination recipient, retrieved from a server.
     * @throws InvalidKeyException        when the {@link PreKeyBundle} is
     *                                    badly formatted.
     * @throws UntrustedIdentityException when the sender's
     *                                    {@link IdentityKey} is not
     *                                    trusted.
     */
    public void process(PreKeyBundle preKey) throws InvalidKeyException, UntrustedIdentityException, SodiumException {
        synchronized (SessionCipher.SESSION_LOCK) {

            if (!identityKeyStore.isTrustedIdentity(remoteAddress, preKey.getIdentityKey(), IdentityKeyStore.Direction.SENDING)) {
                throw new UntrustedIdentityException(remoteAddress.getDid(), preKey.getIdentityKey());
            }

            if (preKey.getSignedPreKey() != null &&
                    !Curve.verifySignature(preKey.getIdentityKey().getPublicKey(),
                            preKey.getSignedPreKey().getBytes(),
                            preKey.getSignedPreKeySignature())) {
                throw new InvalidKeyException("Invalid signature on device key!");
            }

            if (preKey.getSignedPreKey() == null) {
                throw new InvalidKeyException("No signed prekey!");
            }

            SessionRecord sessionRecord = sessionStore.loadSession(remoteAddress);
            ECKeyPair ourBaseKey = Curve.generateKeyPair();
            ECPublicKey theirSignedPreKey = preKey.getSignedPreKey();
            Optional<ECPublicKey> theirOneTimePreKey = Optional.fromNullable(preKey.getPreKey());
            Optional<Integer> theirOneTimePreKeyId = theirOneTimePreKey.isPresent() ? Optional.of(preKey.getPreKeyId()) :
                    Optional.absent();

            AliceProtocolParameters.Builder parameters = AliceProtocolParameters.newBuilder();

            parameters.setOurBaseKey(ourBaseKey)
                    .setOurIdentityKey(identityKeyStore.getIdentityKeyPair())
                    .setTheirIdentityKey(preKey.getIdentityKey())
                    .setTheirSignedPreKey(theirSignedPreKey)
                    .setTheirRatchetKey(theirSignedPreKey)
                    .setTheirOneTimePreKey(theirOneTimePreKey);

            if (!sessionRecord.isFresh()) sessionRecord.archiveCurrentState();

            RatchetingSession.initializeSession(sessionRecord.getSessionState(), parameters.create());

            sessionRecord.getSessionState().setUnacknowledgedPreKeyMessage(theirOneTimePreKeyId, preKey.getSignedPreKeyId(), ourBaseKey.getPublicKey());
            sessionRecord.getSessionState().setLocalRegistrationId(identityKeyStore.getLocalRegistrationId());
            sessionRecord.getSessionState().setRemoteRegistrationId(preKey.getRegistrationId());
            sessionRecord.getSessionState().setAliceBaseKey(ourBaseKey.getPublicKey().getBytes());

            identityKeyStore.saveIdentity(remoteAddress, preKey.getIdentityKey());
            sessionStore.storeSession(remoteAddress, sessionRecord);
        }
    }
}
