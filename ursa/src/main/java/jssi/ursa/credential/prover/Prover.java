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

package jssi.ursa.credential.prover;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.credential.*;
import jssi.ursa.pair.CryptoException;
import jssi.ursa.pair.GroupOrderElement;
import jssi.ursa.registry.RevocationPublicKey;
import jssi.ursa.registry.RevocationRegistry;
import jssi.ursa.registry.Witness;
import jssi.ursa.registry.WitnessSignature;

import java.math.BigInteger;

public class Prover {

    private static final Logger LOG = LoggerFactory.getLogger(Prover.class);

    private static void processPrimaryCredential(
            PrimaryCredentialSignature primaryCredentialSignature,
            BigInteger v_prime)
    {
        primaryCredentialSignature.v = v_prime.add(primaryCredentialSignature.v);
    }

    private static boolean processNonRevocationCredential(
            NonRevocationCredentialSignature nonRevocationCredentialSignature,
            GroupOrderElement vr_prime,
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            RevocationPublicKey revocationPublicKey,
            RevocationRegistry revocationRegistry,
            Witness witness) throws CryptoException {

        BigInteger r_cnxt_m2 = new BigInteger(1, nonRevocationCredentialSignature.m2.toBytes());
        nonRevocationCredentialSignature.vr_prime_prime = vr_prime.addmod(nonRevocationCredentialSignature.vr_prime_prime);

        return WitnessSignature.check(
                nonRevocationCredentialSignature,
                credentialRevocationPublicKey,
                revocationPublicKey,
                revocationRegistry,
                witness,
                r_cnxt_m2);
    }

    /**
     * Updates the credential signature by a master secret blinding data
     *
     * @param credentialSignature
     * @param credentialValues
     * @param signatureCorrectnessProof
     * @param credentialSecretsBlindingFactors
     * @param credentialPublicKey
     * @param issuanceNonce
     * @param revocationPublicKey
     * @param revocationRegistry
     * @param witness
     * @return boolean
     * @throws CryptoException
     *
     * Example
     *
     * CredentialSchemaBuilder builder = CredentialSchema.CredentialSchemaBuilder().builder();
     * builder.addAttr("sex");
     * CredentialSchema credentialSchema = builder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, true);
     *
     * int maxCredentials = 5;
     * boolean isDefault = false;
     * RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
     *               credentialDefinition.getCredentialPublicKey(),
     *               maxCredentials,
     *               isDefault);
     *
     * SimpleTailsAccessor accessor = SimpleTailsAccessor.create(revocationRegistryDefinition.getRevocationTailsGenerator());
     * MasterSecret masterSecret = MasterSecret.create();
     *
     * CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
     * builder.addHidden("master_secret", masterSecret.ms);
     * builder.addKnown("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
     * CredentialValues credentialValues = return builder.build()
     *
     * BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     * BlindedCredentials blindedCredentials = Prover.blindCredentialSecrets(
     *               credentialDefinition.getCredentialPublicKey(),
     *               credentialDefinition.getCredentialKeyCorrectnessProof(),
     *               credentialValues,
     *               credentialNonce);
     *
     * BigInteger issuanceNonce = BigNumber.random(LARGE_NONCE);
     *
     * int revocationIndex = 1;
     * SignedCredential signedCredential = Issuer.signCredentialWithRevocation(
     *                 "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
     *                 blindedCredentials.getBlindedCredentialSecrets(),
     *                 blindedCredentials.getBlindedCredentialSecretsCorrectnessProof(),
     *                 credentialNonce,
     *                 issuanceNonce,
     *                 credentialValues,
     *                 credentialDefinition.getCredentialPublicKey(),
     *                 credentialDefinition.getCredentialPrivateKey());
     *
     * boolean result = Prover.processCredentialSignature(signedCredential.credentialSignature,
     *                 credentialValues,
     *                 signedCredential.signatureCorrectnessProof,
     *                 blindedCredentials.credentialSecretsBlindingFactors,
     *                 credentialDefinition.getCredentialPublicKey(),
     *                 issuanceNonce,
     *                 null, null, ull);
     */
    public static boolean processCredentialSignature(
            CredentialSignature credentialSignature,
            CredentialValues credentialValues,
            SignatureCorrectnessProof signatureCorrectnessProof,
            CredentialSecretsBlindingFactors credentialSecretsBlindingFactors,
            CredentialPublicKey credentialPublicKey,
            BigInteger issuanceNonce,
            RevocationPublicKey revocationPublicKey,
            RevocationRegistry revocationRegistry,
            Witness witness) throws CryptoException

    {
        processPrimaryCredential(
                credentialSignature.p_credential,
                credentialSecretsBlindingFactors.v_prime);


        if(!SignatureCorrectnessProof.check(
                credentialSignature.p_credential,
                credentialValues,
                signatureCorrectnessProof,
                credentialPublicKey.p_key,
                issuanceNonce))
        {
            LOG.error("Fail check Signature correctness proof");
            return false;
        }

        if(credentialSignature.r_credential == null
                && credentialSecretsBlindingFactors.vr_prime == null
                && credentialPublicKey.r_key == null
                && revocationPublicKey == null
                && revocationRegistry == null
                && witness == null)
        {
            LOG.debug("Process only Primary proof");
            return true;
        }

        if(!processNonRevocationCredential(
                credentialSignature.r_credential,
                credentialSecretsBlindingFactors.vr_prime,
                credentialPublicKey.r_key,
                revocationPublicKey,
                revocationRegistry,
                witness))
        {
            LOG.error("Fail process NonRevocation credential");
            return false;
        }
        return true;
    }


    /**
     *
     * @param credentialPublicKey
     * @param credentialKeyCorrectnessProof
     * @param credentialValues
     * @param credentialNonce
     * @return BlindedCredentials
     *
     * Example
     *
     * CredentialSchemaBuilder credentialSchemaBuilder = CredentialSchema.CredentialSchemaBuilder().builder();
     * credentialSchemaBuilder.addAttr("sex");
     * CredentialSchema credentialSchema = credentialSchemaBuilder.build();
     *
     * NonCredentialSchemaBuilder nonBuilder = NonCredentialSchema.NonCredentialSchemaBuilder.builder();
     * nonBuilder.addAttr("master_secret");
     * NonCredentialSchema nonCredentialSchema = nonBuilder.build();;
     *
     * CredentialDefinition credentialDefinition = Issuer.createCredentialDefinition(credentialSchema, nonCredentialSchema, false);
     *
     * MasterSecret masterSecret = MasterSecret.create();
     * BigInteger credentialNonce = BigNumber.random(LARGE_NONCE);
     *
     * CredentialValues.CredentialValuesBuilder credentialValuesBuilder = CredentialValues.builder();
     * credentialValuesBuilder.addHidden("master_secret", masterSecret.ms);
     * CredentialValues credentialValues = credentialValuesBuilder.build()
     *
     * BlindedCredentials blindedCredentials = BlindedCredentials.blindCredentialSecrets(
     *          credentialDefinition.getCredentialPublicKey(),
     *          credentialDefinition.getCredentialKeyCorrectnessProof(),
     *          credentialValues);
     */
    public static BlindedCredentials blindCredentialSecrets(
            CredentialPublicKey credentialPublicKey,
            CredentialKeyCorrectnessProof credentialKeyCorrectnessProof,
            CredentialValues credentialValues,
            BigInteger credentialNonce)
    {
        LOG.debug("Blind credential secrets...");
        if(!CredentialKeyCorrectnessProof.check(credentialPublicKey.p_key, credentialKeyCorrectnessProof)){
            return null;
        }

        PrimaryBlindedCredentialSecretsFactors primaryBlindedCredentialSecretsFactors = PrimaryBlindedCredentialSecretsFactors.create(
                credentialPublicKey.p_key,
                credentialValues);

        RevocationBlindedCredentialSecretsFactors revocationBlindedCredentialSecretsFactors = RevocationBlindedCredentialSecretsFactors.create(
                credentialPublicKey.r_key);

        BlindedCredentialSecrets blindedCredentialSecrets = new BlindedCredentialSecrets(
                primaryBlindedCredentialSecretsFactors.u,
                revocationBlindedCredentialSecretsFactors == null ? null : revocationBlindedCredentialSecretsFactors.ur,
                primaryBlindedCredentialSecretsFactors.hidden_attributes,
                primaryBlindedCredentialSecretsFactors.committed_attributes);

        BlindedCredentialSecretsCorrectnessProof blindedCredentialSecretsCorrectnessProof = BlindedCredentialSecretsCorrectnessProof.create(
                credentialPublicKey.p_key,
                primaryBlindedCredentialSecretsFactors,
                credentialNonce,
                credentialValues);

        CredentialSecretsBlindingFactors credentialSecretsBlindingFactors = new CredentialSecretsBlindingFactors(
                primaryBlindedCredentialSecretsFactors.v_prime,
                revocationBlindedCredentialSecretsFactors == null ? null : revocationBlindedCredentialSecretsFactors.vr_prime);

        return new BlindedCredentials(
                blindedCredentialSecrets,
                credentialSecretsBlindingFactors,
                blindedCredentialSecretsCorrectnessProof);
    }
}
