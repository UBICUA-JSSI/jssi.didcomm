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
package jssi.mls.groups.ratchet;

import org.libsodium.api.Crypto_auth;
import org.libsodium.jni.SodiumException;

/**
 * Each SenderKey is a "chain" of keys, each derived from the previous.
 *
 * At any given point in time, the state of a SenderKey can be represented
 * as the current chain key value, along with its iteration count.  From there,
 * subsequent iterations can be derived, as well as individual message keys from
 * each chain key.
 *
 * @author Moxie Marlinspike
 */
public class SenderChainKey {

    private static final byte[] MESSAGE_KEY_SEED = {0x01};
    private static final byte[] CHAIN_KEY_SEED = {0x02};

    private final int iteration;
    private final byte[] chainKey;

    public SenderChainKey(int iteration, byte[] chainKey) {
        this.iteration = iteration;
        this.chainKey = chainKey;
    }

    public int getIteration() {
        return iteration;
    }

    public SenderMessageKey getSenderMessageKey() {
        return new SenderMessageKey(iteration, getDerivative(MESSAGE_KEY_SEED, chainKey));
    }

    public SenderChainKey getNext() {
        return new SenderChainKey(iteration + 1, getDerivative(CHAIN_KEY_SEED, chainKey));
    }

    public byte[] getSeed() {
        return chainKey;
    }

    private byte[] getDerivative(byte[] seed, byte[] key) {
        try {
            return Crypto_auth.hmacsha256(seed, key);
        } catch (SodiumException e) {
            throw new AssertionError(e);
        }
    }
}
