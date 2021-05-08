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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import jssi.ursa.credential.util.BigNumber;

import java.math.BigInteger;

import static jssi.ursa.credential.util.BigNumber.LARGE_MASTER_SECRET;


/**
 * Secret key encoded in a credential that is used to prove that prover owns the credential; can be used to
 * prove linkage across credentials.
 * Prover blinds master secret, generating BlindedCredentialSecrets and CredentialSecretsBlindingFactors (blinding factors)
 * and sends the BlindedCredentialSecrets to Issuer who then encodes it credential creation.
 * The blinding factors are used by Prover for post processing of issued credentials.
 */
public class MasterSecret {
    @JsonSerialize(using = ToStringSerializer.class) public BigInteger ms;

    @JsonCreator
    public MasterSecret(@JsonProperty("value") BigInteger ms){
        this.ms = ms;
    }

     public static MasterSecret create(){
        BigInteger ms = BigNumber.random(LARGE_MASTER_SECRET);
        ms = new BigInteger("21578029250517794450984707538122537192839006240802068037273983354680998203845", 10);
        return new MasterSecret(ms);
    }
}
