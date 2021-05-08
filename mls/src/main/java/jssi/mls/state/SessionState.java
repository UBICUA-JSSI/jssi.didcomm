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

package jssi.mls.state;


import com.google.protobuf.ByteString;
import jssi.mls.IdentityKey;
import jssi.mls.IdentityKeyPair;
import jssi.mls.InvalidKeyException;
import jssi.mls.ecc.Curve;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPrivateKey;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.kdf.HKDF;
import jssi.mls.ratchet.ChainKey;
import jssi.mls.ratchet.MessageKeys;
import jssi.mls.ratchet.RootKey;
import jssi.mls.state.StorageProtos.SessionStructure.Chain;
import jssi.mls.state.StorageProtos.SessionStructure.PendingKeyExchange;
import jssi.mls.state.StorageProtos.SessionStructure.PendingPreKey;
import jssi.mls.util.Pair;
import jssi.mls.util.guava.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import static jssi.mls.state.StorageProtos.SessionStructure;

public class SessionState {

    private static final Logger LOG = LoggerFactory.getLogger(SessionState.class);

    private static final int MAX_MESSAGE_KEYS = 2000;

    private SessionStructure sessionStructure;

    public SessionState() {
        this.sessionStructure = SessionStructure.newBuilder().build();
    }

    public SessionState(SessionStructure sessionStructure) {
        this.sessionStructure = sessionStructure;
    }

    public SessionState(SessionState copy) {
        this.sessionStructure = copy.sessionStructure.toBuilder().build();
    }

    public SessionStructure getStructure() {
        return sessionStructure;
    }

    public byte[] getAliceBaseKey() {
        return this.sessionStructure.getAliceBaseKey().toByteArray();
    }

    public void setAliceBaseKey(byte[] aliceBaseKey) {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .setAliceBaseKey(ByteString.copyFrom(aliceBaseKey))
                .build();
    }

    public void setSessionVersion(int version) {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .setSessionVersion(version)
                .build();
    }

    public int getSessionVersion() {
        int sessionVersion = this.sessionStructure.getSessionVersion();

        if (sessionVersion == 0) return 2;
        else return sessionVersion;
    }

    public void setRemoteIdentityKey(IdentityKey identityKey) {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .setRemoteIdentityPublic(ByteString.copyFrom(identityKey.getBytes()))
                .build();
    }

    public void setLocalIdentityKey(IdentityKey identityKey) {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .setLocalIdentityPublic(ByteString.copyFrom(identityKey.getBytes()))
                .build();
    }

    public IdentityKey getRemoteIdentityKey() {
        try {
            if (!this.sessionStructure.hasRemoteIdentityPublic()) {
                return null;
            }

            return new IdentityKey(this.sessionStructure.getRemoteIdentityPublic().toByteArray());
        } catch (InvalidKeyException e) {
            LOG.error("SessionRecordV2", e);
            return null;
        }
    }

    public IdentityKey getLocalIdentityKey() {
        try {
            return new IdentityKey(this.sessionStructure.getLocalIdentityPublic().toByteArray());
        } catch (InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    public int getPreviousCounter() {
        return sessionStructure.getPreviousCounter();
    }

    public void setPreviousCounter(int previousCounter) {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .setPreviousCounter(previousCounter)
                .build();
    }

    public RootKey getRootKey() {
        return new RootKey(new HKDF(),
                this.sessionStructure.getRootKey().toByteArray());
    }

    public void setRootKey(RootKey rootKey) {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .setRootKey(ByteString.copyFrom(rootKey.getKeyBytes()))
                .build();
    }

    public ECPublicKey getSenderRatchetKey() {
        return Curve.getECPublicKey(sessionStructure.getSenderChain().getSenderRatchetKey().toByteArray());
    }

    public ECKeyPair getSenderRatchetKeyPair() {
        ECPublicKey publicKey = getSenderRatchetKey();
        ECPrivateKey privateKey = Curve.getECPrivateKey(sessionStructure.getSenderChain()
                .getSenderRatchetKeyPrivate()
                .toByteArray());

        return new ECKeyPair(publicKey, privateKey);
    }

    public boolean hasReceiverChain(ECPublicKey senderEphemeral) {
        return getReceiverChain(senderEphemeral) != null;
    }

    public boolean hasSenderChain() {
        return sessionStructure.hasSenderChain();
    }

    private Pair<Chain, Integer> getReceiverChain(ECPublicKey senderEphemeral) {
        List<Chain> receiverChains = sessionStructure.getReceiverChainsList();
        int index = 0;

        for (Chain receiverChain : receiverChains) {
            ECPublicKey chainSenderRatchetKey = Curve.getECPublicKey(receiverChain.getSenderRatchetKey().toByteArray());

            if (chainSenderRatchetKey.equals(senderEphemeral)) {
                return new Pair<>(receiverChain, index);
            }

            index++;
        }

        return null;
    }

    public ChainKey getReceiverChainKey(ECPublicKey senderEphemeral) {
        Pair<Chain, Integer> receiverChainAndIndex = getReceiverChain(senderEphemeral);
        Chain receiverChain = receiverChainAndIndex.first();

        if (receiverChain == null) {
            return null;
        } else {
            return new ChainKey(new HKDF(),
                    receiverChain.getChainKey().getKey().toByteArray(),
                    receiverChain.getChainKey().getIndex());
        }
    }

    public void addReceiverChain(ECPublicKey senderRatchetKey, ChainKey chainKey) {
        Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                .setKey(ByteString.copyFrom(chainKey.getKey()))
                .setIndex(chainKey.getIndex())
                .build();

        Chain chain = Chain.newBuilder()
                .setChainKey(chainKeyStructure)
                .setSenderRatchetKey(ByteString.copyFrom(senderRatchetKey.getBytes()))
                .build();

        this.sessionStructure = this.sessionStructure.toBuilder().addReceiverChains(chain).build();

        if (this.sessionStructure.getReceiverChainsList().size() > 5) {
            this.sessionStructure = this.sessionStructure.toBuilder()
                    .removeReceiverChains(0)
                    .build();
        }
    }

    public void setSenderChain(ECKeyPair senderRatchetKeyPair, ChainKey chainKey) {
        Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                .setKey(ByteString.copyFrom(chainKey.getKey()))
                .setIndex(chainKey.getIndex())
                .build();

        Chain senderChain = Chain.newBuilder()
                .setSenderRatchetKey(ByteString.copyFrom(senderRatchetKeyPair.getPublicKey().getBytes()))
                .setSenderRatchetKeyPrivate(ByteString.copyFrom(senderRatchetKeyPair.getPrivateKey().getBytes()))
                .setChainKey(chainKeyStructure)
                .build();

        this.sessionStructure = this.sessionStructure.toBuilder().setSenderChain(senderChain).build();
    }

    public ChainKey getSenderChainKey() {
        Chain.ChainKey chainKeyStructure = sessionStructure.getSenderChain().getChainKey();
        return new ChainKey(new HKDF(),
                chainKeyStructure.getKey().toByteArray(), chainKeyStructure.getIndex());
    }


    public void setSenderChainKey(ChainKey nextChainKey) {
        Chain.ChainKey chainKey = Chain.ChainKey.newBuilder()
                .setKey(ByteString.copyFrom(nextChainKey.getKey()))
                .setIndex(nextChainKey.getIndex())
                .build();

        Chain chain = sessionStructure.getSenderChain().toBuilder()
                .setChainKey(chainKey).build();

        this.sessionStructure = this.sessionStructure.toBuilder().setSenderChain(chain).build();
    }

    public boolean hasMessageKeys(ECPublicKey senderEphemeral, int counter) {
        Pair<Chain, Integer> chainAndIndex = getReceiverChain(senderEphemeral);
        Chain chain = chainAndIndex.first();

        if (chain == null) {
            return false;
        }

        List<Chain.MessageKey> messageKeyList = chain.getMessageKeysList();

        for (Chain.MessageKey messageKey : messageKeyList) {
            if (messageKey.getIndex() == counter) {
                return true;
            }
        }

        return false;
    }

    public MessageKeys removeMessageKeys(ECPublicKey senderEphemeral, int counter) {
        Pair<Chain, Integer> chainAndIndex = getReceiverChain(senderEphemeral);
        Chain chain = chainAndIndex.first();

        if (chain == null) {
            return null;
        }

        List<Chain.MessageKey> messageKeyList = new LinkedList<>(chain.getMessageKeysList());
        Iterator<Chain.MessageKey> messageKeyIterator = messageKeyList.iterator();
        MessageKeys result = null;

        while (messageKeyIterator.hasNext()) {
            Chain.MessageKey messageKey = messageKeyIterator.next();

            if (messageKey.getIndex() == counter) {
                result = new MessageKeys(new SecretKeySpec(messageKey.getCipherKey().toByteArray(), "AES"),
                        new SecretKeySpec(messageKey.getMacKey().toByteArray(), "HmacSHA256"),
                        new IvParameterSpec(messageKey.getIv().toByteArray()),
                        messageKey.getIndex());

                messageKeyIterator.remove();
                break;
            }
        }

        Chain updatedChain = chain.toBuilder().clearMessageKeys()
                .addAllMessageKeys(messageKeyList)
                .build();

        this.sessionStructure = this.sessionStructure.toBuilder()
                .setReceiverChains(chainAndIndex.second(), updatedChain)
                .build();

        return result;
    }

    public void setMessageKeys(ECPublicKey senderEphemeral, MessageKeys messageKeys) {
        Pair<Chain, Integer> chainAndIndex = getReceiverChain(senderEphemeral);
        Chain chain = chainAndIndex.first();
        Chain.MessageKey messageKeyStructure = Chain.MessageKey.newBuilder()
                .setCipherKey(ByteString.copyFrom(messageKeys.getCipherKey().getEncoded()))
                .setMacKey(ByteString.copyFrom(messageKeys.getMacKey().getEncoded()))
                .setIndex(messageKeys.getCounter())
                .setIv(ByteString.copyFrom(messageKeys.getIv().getIV()))
                .build();

        Chain.Builder updatedChain = chain.toBuilder().addMessageKeys(messageKeyStructure);

        if (updatedChain.getMessageKeysCount() > MAX_MESSAGE_KEYS) {
            updatedChain.removeMessageKeys(0);
        }

        this.sessionStructure = this.sessionStructure.toBuilder()
                .setReceiverChains(chainAndIndex.second(),
                        updatedChain.build())
                .build();
    }

    public void setReceiverChainKey(ECPublicKey senderEphemeral, ChainKey chainKey) {
        Pair<Chain, Integer> chainAndIndex = getReceiverChain(senderEphemeral);
        Chain chain = chainAndIndex.first();

        Chain.ChainKey chainKeyStructure = Chain.ChainKey.newBuilder()
                .setKey(ByteString.copyFrom(chainKey.getKey()))
                .setIndex(chainKey.getIndex())
                .build();

        Chain updatedChain = chain.toBuilder().setChainKey(chainKeyStructure).build();

        this.sessionStructure = this.sessionStructure.toBuilder()
                .setReceiverChains(chainAndIndex.second(), updatedChain)
                .build();
    }

    public void setPendingKeyExchange(int sequence,
                                      ECKeyPair ourBaseKey,
                                      ECKeyPair ourRatchetKey,
                                      IdentityKeyPair ourIdentityKey) {
        PendingKeyExchange structure =
                PendingKeyExchange.newBuilder()
                        .setSequence(sequence)
                        .setLocalBaseKey(ByteString.copyFrom(ourBaseKey.getPublicKey().getBytes()))
                        .setLocalBaseKeyPrivate(ByteString.copyFrom(ourBaseKey.getPrivateKey().getBytes()))
                        .setLocalRatchetKey(ByteString.copyFrom(ourRatchetKey.getPublicKey().getBytes()))
                        .setLocalRatchetKeyPrivate(ByteString.copyFrom(ourRatchetKey.getPrivateKey().getBytes()))
                        .setLocalIdentityKey(ByteString.copyFrom(ourIdentityKey.getPublicKey().getBytes()))
                        .setLocalIdentityKeyPrivate(ByteString.copyFrom(ourIdentityKey.getPrivateKey().getBytes()))
                        .build();

        this.sessionStructure = this.sessionStructure.toBuilder()
                .setPendingKeyExchange(structure)
                .build();
    }

    public int getPendingKeyExchangeSequence() {
        return sessionStructure.getPendingKeyExchange().getSequence();
    }

    public ECKeyPair getPendingKeyExchangeBaseKey() throws InvalidKeyException {
        ECPublicKey publicKey = Curve.getECPublicKey(sessionStructure.getPendingKeyExchange()
                .getLocalBaseKey().toByteArray());

        ECPrivateKey privateKey = Curve.getECPrivateKey(sessionStructure.getPendingKeyExchange()
                .getLocalBaseKeyPrivate()
                .toByteArray());

        return new ECKeyPair(publicKey, privateKey);
    }

    public ECKeyPair getPendingKeyExchangeRatchetKey() throws InvalidKeyException {
        ECPublicKey publicKey = Curve.getECPublicKey(sessionStructure.getPendingKeyExchange()
                .getLocalRatchetKey().toByteArray());

        ECPrivateKey privateKey = Curve.getECPrivateKey(sessionStructure.getPendingKeyExchange()
                .getLocalRatchetKeyPrivate()
                .toByteArray());

        return new ECKeyPair(publicKey, privateKey);
    }

    public IdentityKeyPair getPendingKeyExchangeIdentityKey() throws InvalidKeyException {
        IdentityKey publicKey = new IdentityKey(sessionStructure.getPendingKeyExchange()
                .getLocalIdentityKey().toByteArray());

        ECPrivateKey privateKey = Curve.getECPrivateKey(sessionStructure.getPendingKeyExchange()
                .getLocalIdentityKeyPrivate()
                .toByteArray());

        return new IdentityKeyPair(publicKey, privateKey);
    }

    public boolean hasPendingKeyExchange() {
        return sessionStructure.hasPendingKeyExchange();
    }

    public void setUnacknowledgedPreKeyMessage(Optional<Integer> preKeyId, int signedPreKeyId, ECPublicKey baseKey) {
        PendingPreKey.Builder pending = PendingPreKey.newBuilder()
                .setSignedPreKeyId(signedPreKeyId)
                .setBaseKey(ByteString.copyFrom(baseKey.getBytes()));

        if (preKeyId.isPresent()) {
            pending.setPreKeyId(preKeyId.get());
        }

        this.sessionStructure = this.sessionStructure.toBuilder()
                .setPendingPreKey(pending.build())
                .build();
    }

    public boolean hasUnacknowledgedPreKeyMessage() {
        return this.sessionStructure.hasPendingPreKey();
    }

    public UnacknowledgedPreKeyMessageItems getUnacknowledgedPreKeyMessageItems() {
        Optional<Integer> preKeyId;

        if (sessionStructure.getPendingPreKey().hasPreKeyId()) {
            preKeyId = Optional.of(sessionStructure.getPendingPreKey().getPreKeyId());
        } else {
            preKeyId = Optional.absent();
        }

        return new UnacknowledgedPreKeyMessageItems(preKeyId,
                        sessionStructure.getPendingPreKey().getSignedPreKeyId(),
                        Curve.getECPublicKey(sessionStructure.getPendingPreKey()
                                .getBaseKey()
                                .toByteArray()));
    }

    public void clearUnacknowledgedPreKeyMessage() {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .clearPendingPreKey()
                .build();
    }

    public void setRemoteRegistrationId(int registrationId) {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .setRemoteRegistrationId(registrationId)
                .build();
    }

    public int getRemoteRegistrationId() {
        return this.sessionStructure.getRemoteRegistrationId();
    }

    public void setLocalRegistrationId(int registrationId) {
        this.sessionStructure = this.sessionStructure.toBuilder()
                .setLocalRegistrationId(registrationId)
                .build();
    }

    public int getLocalRegistrationId() {
        return this.sessionStructure.getLocalRegistrationId();
    }

    public byte[] serialize() {
        return sessionStructure.toByteArray();
    }

    public static class UnacknowledgedPreKeyMessageItems {
        private final Optional<Integer> preKeyId;
        private final int signedPreKeyId;
        private final ECPublicKey baseKey;

        public UnacknowledgedPreKeyMessageItems(Optional<Integer> preKeyId,
                                                int signedPreKeyId,
                                                ECPublicKey baseKey) {
            this.preKeyId = preKeyId;
            this.signedPreKeyId = signedPreKeyId;
            this.baseKey = baseKey;
        }


        public Optional<Integer> getPreKeyId() {
            return preKeyId;
        }

        public int getSignedPreKeyId() {
            return signedPreKeyId;
        }

        public ECPublicKey getBaseKey() {
            return baseKey;
        }
    }
}
