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

package jssi.ursa.credential.zerokp;

import jssi.ursa.credential.CredentialSchema;
import jssi.ursa.credential.CredentialValues;
import jssi.ursa.credential.NonCredentialSchema;
import jssi.ursa.credential.proof.SubProofRequest;
import jssi.ursa.credential.prover.MasterSecret;
import jssi.ursa.credential.util.BigNumber;

import java.math.BigInteger;

import static jssi.ursa.credential.util.BigNumber.LARGE_NONCE;

public class ZeroKP {

    public static final String PROVER_DID = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";
    public static final String LINK_SECRET = "master_secret";

    public static BigInteger getCredentialIssuanceNonce(){
        BigInteger nonce = BigNumber.random(LARGE_NONCE);
        nonce = new BigInteger("56533754654551822200471", 10);
        return nonce;
    }

    public static BigInteger getCredentialNonce(){
        BigInteger nonce = BigNumber.random(LARGE_NONCE);
        nonce = new BigInteger("400156503076115782845986", 10);
        return nonce;
    }

    public static CredentialSchema gvtCredentialSchema() {
        CredentialSchema.CredentialSchemaBuilder builder = CredentialSchema.builder();
        builder.addAttr("name");
        builder.addAttr("sex");
        builder.addAttr("age");
        builder.addAttr("height");
        return builder.build();
    }

    public static CredentialSchema xyzCredentialSchema() {
        CredentialSchema.CredentialSchemaBuilder builder = CredentialSchema.builder();
        builder.addAttr("status");
        builder.addAttr("period");
        return builder.build();
    }

    public static CredentialSchema pqrCredentialSchema() {
        CredentialSchema.CredentialSchemaBuilder builder = CredentialSchema.builder();
        builder.addAttr("name");
        builder.addAttr("address");
        return builder.build();
    }

    public static NonCredentialSchema nonCredentialSchema() {
        NonCredentialSchema.NonCredentialSchemaBuilder builder = NonCredentialSchema.builder();
        builder.addAttr("master_secret");
        return builder.build();
    }

    public static CredentialValues gvtCredentialValues(MasterSecret master_secret) {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", master_secret.ms);
        builder.addKnown("name", "1139481716457488690172217916278103335");
        builder.addKnown("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
        builder.addKnown("age", "28");
        builder.addKnown("height", "175");
        return builder.build();
    }

    public static CredentialValues xyzCredentialValues(MasterSecret master_secret) {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", master_secret.ms);
        builder.addKnown("status", "51792877103171595686471452153480627530895");
        builder.addKnown("period", "8");
        return builder.build();
    }

    public static CredentialValues pqrCredentialValues(MasterSecret master_secret) {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", master_secret.ms);
        builder.addKnown("name", "1139481716457488690172217916278103335");
        builder.addKnown("address", "51792877103171595686471452153480627530891");
        return builder.build();
    }

    public static CredentialValues pqrCredentialValues_1(MasterSecret master_secret) {
        CredentialValues.CredentialValuesBuilder builder = CredentialValues.builder();
        builder.addHidden("master_secret", master_secret.ms);
        builder.addKnown("name", "7181645748869017221791627810333511394");
        builder.addKnown("address", "51792877103171595686471452153480627530891");
        return builder.build();
    }

    public static SubProofRequest gvtSubProofRequest() {
        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("name");
        builder.addPredicate("age", "GE", 18);
        return builder.build();
    }

    public static SubProofRequest xyzSubProofRequest() {
        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("status");
        builder.addPredicate("period", "GE", 4);
        return builder.build();
    }

    public static SubProofRequest pqrSubProofRequest() {
        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("address");
        return builder.build();
    }

    public static SubProofRequest gvtSubProofRequest_1() {
        SubProofRequest.SubProofRequestBuilder builder = SubProofRequest.builder();
        builder.addRevealedAttr("sex");
        return builder.build();
    }
}
