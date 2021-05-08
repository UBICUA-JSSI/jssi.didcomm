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

import jssi.ursa.util.BigIntegers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.credential.CredentialRevocationPublicKey;
import jssi.ursa.credential.NonRevocationCredentialSignature;
import jssi.ursa.pair.*;

import java.math.BigInteger;


public class WitnessSignature {

    private static final Logger LOG = LoggerFactory.getLogger(WitnessSignature.class);

    public PointG2 sigma_i;
    public PointG2 u_i;
    public PointG1 g_i;

    public WitnessSignature(PointG2 sigma_i, PointG2 u_i, PointG1 g_i){
        this.sigma_i = sigma_i;
        this.u_i = u_i;
        this.g_i = g_i;
    }

    public static boolean check(
            NonRevocationCredentialSignature nonRevocationCredentialSignature,
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            RevocationPublicKey revocationPublicKey,
            RevocationRegistry revocationRegistry,
            Witness witness,
            BigInteger r_cnxt_m2) throws CryptoException
    {
        LOG.debug("Check Witness signature...");

        if(revocationPublicKey == null || revocationRegistry == null || witness == null){
            LOG.debug("Optional parameters NULL. Witness signature checked");
            return true;
        }

        Pair z_calc = Pair.pair(nonRevocationCredentialSignature.witness_signature.g_i, revocationRegistry.accumulator)
                .mul(Pair.pair(credentialRevocationPublicKey.g, witness.omega).inverse());

        if (!z_calc.equals(revocationPublicKey.z)) {
            LOG.error("Issuer is sending incorrect data");
            return false;
        }

        Pair pair_gg_calc = Pair.pair(
                credentialRevocationPublicKey.pk.add(nonRevocationCredentialSignature.g_i),
                nonRevocationCredentialSignature.witness_signature.sigma_i);

        Pair pair_gg = Pair.pair(credentialRevocationPublicKey.g, credentialRevocationPublicKey.g_dash);

        if (!pair_gg_calc.equals(pair_gg)) {
            LOG.error("Issuer is sending incorrect data");
            return false;
        }

        GroupOrderElement m2 = GroupOrderElement.fromBytes(BigIntegers.asUnsignedByteArray(r_cnxt_m2));

        Pair pair_h1 = Pair.pair(
                nonRevocationCredentialSignature.sigma,
                credentialRevocationPublicKey
                        .y
                        .add(credentialRevocationPublicKey.h_cap.mul(nonRevocationCredentialSignature.c)));

        Pair pair_h2 = Pair.pair(
                credentialRevocationPublicKey
                        .h0
                        .add(credentialRevocationPublicKey.h1.mul(m2))
                        .add(credentialRevocationPublicKey.h2.mul(nonRevocationCredentialSignature.vr_prime_prime))
                        .add(nonRevocationCredentialSignature.g_i),
                credentialRevocationPublicKey.h_cap);

        if (!pair_h1.equals(pair_h2)) {
            LOG.error("Issuer is sending incorrect data");
            return false;
        }

        LOG.debug("Check Witness signature... OK");
        return true;
    }
}
