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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.credential.util.BigNumber;
import jssi.ursa.util.Bytes;

import java.math.BigInteger;
import java.security.SecureRandom;

import static jssi.ursa.util.BigIntegers.asUnsignedByteArray;

public class SignatureCorrectnessProof {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureCorrectnessProof.class);

    @JsonSerialize(using = ToStringSerializer.class) public BigInteger se;
    @JsonSerialize(using = ToStringSerializer.class) public BigInteger c;

    @JsonCreator
    public SignatureCorrectnessProof(
            @JsonProperty("se") BigInteger se,
            @JsonProperty("c") BigInteger c)
    {
        this.se = se;
        this.c = c;
    }

    public static SignatureCorrectnessProof create(
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            CredentialPrimaryPrivateKey credentialPrimaryPrivateKey,
            PrimaryCredentialSignature primaryCredentialSignature,
            BigInteger q,
            BigInteger nonce)
    {
        LOG.debug("Create Signature correctness proof...");
        BigInteger n = credentialPrimaryPrivateKey.p.multiply(credentialPrimaryPrivateKey.q);
        BigInteger r = BigNumber.randomInRange(BigInteger.ZERO, n, new SecureRandom());
        r = new BigInteger("6355086599653879826316700099928903465759924565682653297540990486160410136991969646604012568191576052570982028627086748382054319397088948628665022843282950799083156383516421449932691541760677147872377591267323656783938723945915297920233965100454678367417561768144216659060966399182536425206811620699453941460281449071103436526749575365638254352831881150836568830779323361579590121888491911166612382507532248659384681554612887580241255323056245170208421770819447066550669981130450421507202133758209950007973511221223647764045990479619451838104977691662868482078262695232806059726002249095643117917855811948311863670130", 10);

        BigInteger a_cap = q.modPow(r, credentialPrimaryPublicKey.n);

        byte[] values = asUnsignedByteArray(q);
        values = Bytes.concat(values, asUnsignedByteArray(primaryCredentialSignature.a));
        values = Bytes.concat(values, asUnsignedByteArray(a_cap));
        values = Bytes.concat(values, asUnsignedByteArray(nonce));

        BigInteger c = new BigInteger(1, CredentialHelper.hash(values));

        BigInteger se = r.subtract(c.multiply(primaryCredentialSignature.e.modInverse(n)).mod(n)).mod(n);

        return new SignatureCorrectnessProof(se, c);
    }

    public static boolean check(
            PrimaryCredentialSignature primaryCredentialSignature,
            CredentialValues credentialValues,
            SignatureCorrectnessProof signatureCorrectnessProof,
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            BigInteger nonce)
    {
        LOG.debug("Check Signature correctness proof...");
        if (!primaryCredentialSignature.e.isProbablePrime(100)) {
            LOG.error("Invalid Signature correctness proof");
            return false;
        }

        for(String attr : credentialValues.getValues().keySet()){
            CredentialValue value = credentialValues.getValues().get(attr);
            if((value.type == CredentialValue.Type.KNOWN || value.type == CredentialValue.Type.HIDDEN) && !credentialPrimaryPublicKey.r.containsKey(attr)){
                LOG.error(String.format("Value by key '%s' not found in Credential primary public key", attr));
                return false;
            }
        }

        BigInteger rx =  CredentialHelper.getPedersenCommitment(
                credentialPrimaryPublicKey.s,
                primaryCredentialSignature.v,
                credentialPrimaryPublicKey.rctxt,
                primaryCredentialSignature.m_2,
                credentialPrimaryPublicKey.n);

        for(String attr : credentialValues.getValues().keySet()){
            CredentialValue value = credentialValues.getValues().get(attr);
            if((value.type == CredentialValue.Type.KNOWN || value.type == CredentialValue.Type.HIDDEN) && credentialPrimaryPublicKey.r.containsKey(attr)){
                rx = rx.multiply(credentialPrimaryPublicKey.r.get(attr).modPow(value.value, credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);
            }
        }

        BigInteger q = credentialPrimaryPublicKey.z.multiply(rx.modInverse(credentialPrimaryPublicKey.n)).mod(credentialPrimaryPublicKey.n);
        BigInteger expected_q = primaryCredentialSignature.a.modPow(primaryCredentialSignature.e, credentialPrimaryPublicKey.n);

        if (!q.equals(expected_q)) {
            LOG.error("Invalid Signature correctness proof q != q'");
            return false;
        }

        BigInteger degree = signatureCorrectnessProof.c.add(signatureCorrectnessProof.se.multiply(primaryCredentialSignature.e));
        BigInteger a_cap = primaryCredentialSignature.a.modPow(degree, credentialPrimaryPublicKey.n);

        byte[] values = asUnsignedByteArray(q);
        values = Bytes.concat(values, asUnsignedByteArray(primaryCredentialSignature.a));
        values = Bytes.concat(values, asUnsignedByteArray(a_cap));
        values = Bytes.concat(values, asUnsignedByteArray(nonce));

        BigInteger c = new BigInteger(1, CredentialHelper.hash(values));
        boolean valid = signatureCorrectnessProof.c.equals(c);

        if(!valid){
            LOG.error("Invalid Signature correctness proof");
            return false;
        }

        LOG.debug("Check Signature correctness proof... OK");
        return true;
    }
}
