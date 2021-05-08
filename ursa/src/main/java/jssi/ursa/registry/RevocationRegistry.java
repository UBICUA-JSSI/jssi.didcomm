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

package jssi.ursa.registry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.credential.CredentialRevocationPublicKey;
import jssi.ursa.pair.PointG2;

// Revocation Registry contains accumulator.
// Must be published by Issuer on a tamper-evident and highly available storage
// Used by prover to prove that a credential hasn't revoked by the issuer
// isDefault - Type of issuance.
// If true all indices are assumed to be issued and initial accumulator is calculated over all indices
// If false nothing is issued initially accumulator is 1
public class RevocationRegistry {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationRegistry.class);

    public Accumulator accumulator;

    public RevocationRegistry(Accumulator accumulator){
        this.accumulator = accumulator;
    }

    public static RevocationRegistry create(
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            RevocationPrivateKey revocationPrivateKey,
            int maxCredentials,
            boolean isDefault)
    {
        LOG.debug("Create Revocation registry...");

        Accumulator accumulator = new Accumulator(PointG2.infinity());

        if (isDefault) {

            for (int i = 1; i <= maxCredentials; i++) {
                int index = maxCredentials + 1 - i;
                accumulator = new Accumulator(accumulator.add(Tail.create(
                        index,
                        credentialRevocationPublicKey.g_dash,
                        revocationPrivateKey.gamma)));
            }
        }

        return new RevocationRegistry(accumulator);
    }
}
