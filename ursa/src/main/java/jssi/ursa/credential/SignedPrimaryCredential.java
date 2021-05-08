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

import java.math.BigInteger;

public class SignedPrimaryCredential {

    private static final Logger LOG = LoggerFactory.getLogger(SignedPrimaryCredential.class);

    public BigInteger a;
    public BigInteger q;

    public SignedPrimaryCredential(BigInteger a, BigInteger q){
        this.a = a;
        this.q = q;
    }

    public static SignedPrimaryCredential create(
            CredentialPublicKey credentialPublicKey,
            CredentialPrivateKey credentialPrivateKey,
            BigInteger credentialContext,
            CredentialValues credentialValues,
            BigInteger v,
            BlindedCredentialSecrets blindedCredentialSecrets,
            BigInteger e)
    {
        LOG.debug("Sign Primary credential...");
        CredentialPrimaryPublicKey credentialPrimaryPublicKey = credentialPublicKey.p_key;
        CredentialPrimaryPrivateKey credentialPrimaryPrivateKey = credentialPrivateKey.p_key;
        BigInteger rx = credentialPrimaryPublicKey.s.modPow(v, credentialPrimaryPublicKey.n);

        if (!blindedCredentialSecrets.u.equals(BigInteger.ZERO)) {
            rx = rx.multiply(blindedCredentialSecrets.u).mod(credentialPrimaryPublicKey.n);
        }

        rx = rx.multiply(credentialPrimaryPublicKey.rctxt.modPow(credentialContext, credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);

        for(String attr : credentialValues.getValues().keySet()){
            CredentialValue value = credentialValues.getValues().get(attr);
            if(value.type != CredentialValue.Type.KNOWN){
                continue;
            }
            BigInteger pk_r = credentialPrimaryPublicKey.r.get(attr);
            rx = pk_r.modPow(value.value, credentialPrimaryPublicKey.n).multiply(rx).mod(credentialPrimaryPublicKey.n);
        }

        BigInteger q = credentialPrimaryPublicKey.z.multiply(rx.modInverse(credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);
        BigInteger n = credentialPrimaryPrivateKey.p.multiply(credentialPrimaryPrivateKey.q);
        BigInteger e_inverse = e.modInverse(n);
        BigInteger a = q.modPow(e_inverse, credentialPrimaryPublicKey.n);

        return new SignedPrimaryCredential(a, q);
    }

}
