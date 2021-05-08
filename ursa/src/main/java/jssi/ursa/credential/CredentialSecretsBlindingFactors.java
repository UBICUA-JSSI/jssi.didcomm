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

import jssi.ursa.pair.GroupOrderElement;

import java.math.BigInteger;

/**
 * CredentialSecretsBlindingFactors used by Prover for post processing of credentials received from Issuer
 */
public class CredentialSecretsBlindingFactors {
    public BigInteger v_prime;
    public GroupOrderElement vr_prime;

    public CredentialSecretsBlindingFactors(BigInteger v_prime, GroupOrderElement vr_prime){
        this.v_prime = v_prime;
        this.vr_prime = vr_prime;
    }
}
