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
import jssi.ursa.pair.PointG1;

public class RevocationBlindedCredentialSecretsFactors {
    public PointG1 ur;
    public GroupOrderElement vr_prime;

    public RevocationBlindedCredentialSecretsFactors(PointG1 ur, GroupOrderElement vr_prime){
        this.ur = ur;
        this.vr_prime = vr_prime;
    }

    public static RevocationBlindedCredentialSecretsFactors create(
            CredentialRevocationPublicKey credentialRevocationPublicKey)
    {
        if(credentialRevocationPublicKey == null){
            return null;
        }
        GroupOrderElement vr_prime = new GroupOrderElement();
        PointG1 ur = credentialRevocationPublicKey.h2.mul(vr_prime);
        return new RevocationBlindedCredentialSecretsFactors(ur, vr_prime);
    }
}
