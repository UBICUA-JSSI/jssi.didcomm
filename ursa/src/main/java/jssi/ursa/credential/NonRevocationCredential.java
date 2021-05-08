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

package jssi.ursa.credential;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.pair.CryptoException;
import jssi.ursa.pair.GroupOrderElement;
import jssi.ursa.pair.PointG1;
import jssi.ursa.pair.PointG2;
import jssi.ursa.registry.*;
import jssi.ursa.util.Bytes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static jssi.ursa.util.BigIntegers.asUnsignedByteArray;

/// isDefault - Type of issuance.
/// If true all indices are assumed to be issued and initial accumulator is calculated over all indices
/// If false nothing is issued initially accumulator is 1
public class NonRevocationCredential {

    private static final Logger LOG = LoggerFactory.getLogger(NonRevocationCredential.class);

    public NonRevocationCredentialSignature nonRevocationCredentialSignature;
    public RevocationRegistryDelta revocationRegistryDelta;

    public NonRevocationCredential(NonRevocationCredentialSignature nonRevocationCredentialSignature, RevocationRegistryDelta revocationRegistryDelta) {
            this.nonRevocationCredentialSignature = nonRevocationCredentialSignature;
            this.revocationRegistryDelta = revocationRegistryDelta;
    }

    public static <E extends RevocationTailsAccessor> NonRevocationCredential create(
            int rev_idx,
            BigInteger credentialContext,
            BlindedCredentialSecrets blindedCredentialSecrets,
            CredentialPublicKey credentialPublicKey,
            CredentialPrivateKey credentialPrivateKey,
            int maxCredentials,
            boolean isDefault,
            RevocationRegistry revocationRegistry,
            RevocationPrivateKey revocationPrivateKey,
            E revocationTailsAccessor) throws CryptoException
    {
        LOG.debug("Create Non revocation credential...");
        PointG1 ur = blindedCredentialSecrets.ur;
        if(ur == null) {
            LOG.error("No revocation part present in blinded master secret");
            return null;
        }

        CredentialRevocationPublicKey credentialRevocationPublicKey = credentialPublicKey.r_key;
        if(credentialRevocationPublicKey == null) {
            LOG.error("No revocation part present in credential revocation public key.er secret");
            return null;
        }

        CredentialRevocationPrivateKey credentialRevocationPrivateKey = credentialPrivateKey.r_key;
        if(credentialRevocationPrivateKey == null) {
            LOG.error("No revocation part present in credential revocation private key");
            return null;
        }

        GroupOrderElement vr_prime_prime = new GroupOrderElement();
        GroupOrderElement c = new GroupOrderElement();
        GroupOrderElement m2 = GroupOrderElement.fromBytes(asUnsignedByteArray(credentialContext));

        byte[] i_bytes = Bytes.toBytes(rev_idx);
        GroupOrderElement pow = GroupOrderElement.fromBytes(i_bytes);
        pow = revocationPrivateKey.gamma.powmod(pow);
        PointG1 g_i = credentialRevocationPublicKey.g.mul(pow);

        PointG1 sigma = credentialRevocationPublicKey
                .h0
                .add(credentialRevocationPublicKey.h1.mul(m2))
                .add(ur)
                .add(g_i)
                .add(credentialRevocationPublicKey.h2.mul(vr_prime_prime))
                .mul(credentialRevocationPrivateKey.x.addmod(c).inverse());

        PointG2 sigma_i = credentialRevocationPublicKey.g_dash.mul(
                credentialRevocationPrivateKey
                        .sk
                        .addmod(revocationPrivateKey.gamma.powmod(GroupOrderElement.fromBytes(Bytes.toBytes(rev_idx))))
                        .inverse());

        PointG2 u_i = credentialRevocationPublicKey
                .u
                .mul(revocationPrivateKey.gamma.powmod(GroupOrderElement.fromBytes(Bytes.toBytes(rev_idx))));

        int index = maxCredentials + 1 - rev_idx;

        RevocationRegistryDelta revocationRegistryDelta = null;

        if (!isDefault) {
            Accumulator previous = revocationRegistry.accumulator;
            Tail tail = revocationTailsAccessor.access(index);
            revocationRegistry.accumulator = revocationRegistry.accumulator.add(tail);
            List<Integer> issued = new ArrayList<>();
            issued.add(rev_idx);
            List<Integer> revoked = new ArrayList<>();
            revocationRegistryDelta = new RevocationRegistryDelta(previous, revocationRegistry.accumulator, issued, revoked);
        }

        WitnessSignature witnessSignature = new WitnessSignature(sigma_i, u_i, g_i);

        NonRevocationCredentialSignature nonRevocationCredentialSignature = new NonRevocationCredentialSignature(
                sigma,
                c,
                vr_prime_prime,
                witnessSignature,
                g_i,
                rev_idx,
                m2);

        return new NonRevocationCredential(nonRevocationCredentialSignature, revocationRegistryDelta);
    }
}
