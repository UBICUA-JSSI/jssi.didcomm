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
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.credential.util.BigNumber;
import jssi.ursa.util.Bytes;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import static jssi.ursa.util.BigIntegers.asUnsignedByteArray;

public class CredentialKeyCorrectnessProof {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialKeyCorrectnessProof.class);

    @JsonProperty("c")
    public BigInteger c;
    @JsonProperty("xz_cap")
    public BigInteger xz_cap;
    @JsonProperty("xr_cap")
    @JsonDeserialize(using = Deserializer.class)
    public Map<String, BigInteger> xr_cap;

    @JsonCreator
    public CredentialKeyCorrectnessProof(@JsonProperty("c") BigInteger c,
                                         @JsonProperty("xz_cap") BigInteger xz_cap,
                                         @JsonProperty("xr_cap") Map<String, BigInteger> xr_cap){
        this.c = c;
        this.xz_cap = xz_cap;
        this.xr_cap = xr_cap;
    }

    static class Deserializer extends StdDeserializer<Map<String, BigInteger>> {

        protected Deserializer() {
            this(null);
        }

        protected Deserializer(Class<?> vc) {
            super(vc);
        }

        @Override
        public Map<String, BigInteger> deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException, JsonProcessingException {

            Map<String, BigInteger> result = new LinkedHashMap<>();
            ObjectCodec codec = parser.getCodec();
            TreeNode node = codec.readTree(parser);

            if (node.isArray()) {
                for (JsonNode array : (ArrayNode) node) {
                    String attr = array.get(0).asText();
                    BigInteger value = new BigInteger(array.get(1).asText(), 10);
                    result.put(attr, value);
                }
            }
            return result;
        }
    }

    public static CredentialKeyCorrectnessProof create(
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            CredentialPrimaryPrivateKey credentialPrimaryPrivateKey,
            CredentialPrimaryPublicKeyMetadata credentialPrimaryPublicKeyMetadata)
    {
        LOG.debug("Create Credential key correctness proof...");
        BigInteger xz_tilda = BigNumber.genX(credentialPrimaryPrivateKey.p, credentialPrimaryPrivateKey.q);
        Map<String, BigInteger> xr_tilda = new LinkedHashMap<>();
        for(String key : credentialPrimaryPublicKey.r.keySet()) {
            xr_tilda.put(key, BigNumber.genX(credentialPrimaryPrivateKey.p, credentialPrimaryPrivateKey.q));
        }

        BigInteger z_tilda = credentialPrimaryPublicKey.s.modPow(xz_tilda, credentialPrimaryPublicKey.n);
        Map<String, BigInteger> r_tilda =  new LinkedHashMap<>();
        for(String key : xr_tilda.keySet()) {
            BigInteger value = xr_tilda.get(key);
            r_tilda.put(key, credentialPrimaryPublicKey.s.modPow(value, credentialPrimaryPublicKey.n));
        }

        List<String> ordered_attrs = new ArrayList<>();

        byte[] values = asUnsignedByteArray(credentialPrimaryPublicKey.z);
        for(String key : credentialPrimaryPublicKey.r.keySet()){
            values = Bytes.concat(values, asUnsignedByteArray(credentialPrimaryPublicKey.r.get(key)));
            ordered_attrs.add(key);
        }
        values = Bytes.concat(values, asUnsignedByteArray(z_tilda));
        for(String attr : ordered_attrs){
            values = Bytes.concat(values, asUnsignedByteArray(r_tilda.get(attr)));
        }

        BigInteger c = new BigInteger(1, CredentialHelper.hash(values));
        BigInteger xz_cap = c.multiply(credentialPrimaryPublicKeyMetadata.xz).add(xz_tilda);

        Map<String, BigInteger> xr_cap =  new LinkedHashMap<>();
        for(String key : ordered_attrs){
            BigInteger xr_tilda_value = xr_tilda.get(key);
            BigInteger value = c.multiply(credentialPrimaryPublicKeyMetadata.xr.get(key)).add(xr_tilda_value);
            xr_cap.put(key, value);
        }

        return new CredentialKeyCorrectnessProof(c, xz_cap, xr_cap);
    }


    public static boolean check (
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            CredentialKeyCorrectnessProof credentialKeyCorrectnessProof)
    {

        LOG.debug("Check Credential key correctness proof...");
        Set<String> correctness_names = credentialKeyCorrectnessProof.xr_cap.keySet();

        for (String r_key : credentialPrimaryPublicKey.r.keySet()) {
            if (!correctness_names.contains(r_key)) {
                //V1 didn't include "master_secret" in the correctness proof
                //so for now if this is the only missing key, its okay
                //In the future this "if" statement should be removed
                if (r_key != "master_secret") {
                    LOG.error(String.format("Value by key '%s' not found in key_correctness_proof.xr_cap", r_key));
                    return false;
                }
            }
        }

        for (String correctness_name : correctness_names) {
            if (!credentialPrimaryPublicKey.r.keySet().contains(correctness_name)) {
                LOG.error(String.format("Public key doesn't contains item for %s key in key_correctness_proof.xr_cap", correctness_name));
                return false;
            }
        }

        List<BigInteger> ordered_r_values = new ArrayList<>();
        List<BigInteger> ordered_r_cap_values = new ArrayList<>();

        for(String key : credentialKeyCorrectnessProof.xr_cap.keySet()){
            BigInteger xr_cap_value = credentialKeyCorrectnessProof.xr_cap.get(key);
            BigInteger r_value = credentialPrimaryPublicKey.r.get(key);
            ordered_r_values.add(r_value);
            BigInteger r_inverse = r_value.modInverse(credentialPrimaryPublicKey.n);
            BigInteger val = CredentialHelper.getPedersenCommitment(
                    r_inverse,
                    credentialKeyCorrectnessProof.c,
                    credentialPrimaryPublicKey.s,
                    xr_cap_value,
                    credentialPrimaryPublicKey.n);

            ordered_r_cap_values.add(val);
        }

        byte[] values = asUnsignedByteArray(credentialPrimaryPublicKey.z);
        for (BigInteger val : ordered_r_values) {
            values = Bytes.concat(values, asUnsignedByteArray(val));
        }

        BigInteger z_inverse = credentialPrimaryPublicKey.z.modInverse(credentialPrimaryPublicKey.n);
        BigInteger z_cap = CredentialHelper.getPedersenCommitment(
                z_inverse,
                credentialKeyCorrectnessProof.c,
                credentialPrimaryPublicKey.s,
                credentialKeyCorrectnessProof.xz_cap,
                credentialPrimaryPublicKey.n);

        values = Bytes.concat(values, asUnsignedByteArray(z_cap));
        for (BigInteger val : ordered_r_cap_values) {
            values = Bytes.concat(values, asUnsignedByteArray(val));
        }

        BigInteger c = new BigInteger(1, CredentialHelper.hash(values));
        boolean valid = credentialKeyCorrectnessProof.c.equals(c);

        if(!valid){
            LOG.error("Invalid Credential key correctness proof");
            return false;
        }

        LOG.debug("Check Credential key correctness proof... OK");
        return true;
    }
}
