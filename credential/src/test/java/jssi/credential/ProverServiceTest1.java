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

package jssi.credential;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.Test;
import jssi.credential.credential.AttributeValue;
import jssi.credential.credential.Credential;
import jssi.credential.credential.CredentialAttrTagPolicy;
import jssi.credential.revocation.RevocationRegistryId;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static jssi.credential.ProverService.ATTRIBUTE_EXISTENCE_MARKER;

class ProverServiceTest1 {

    private static String SCHEMA_ID = "NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0";
    private static String SCHEMA_ISSUER_DID = "NcYxiDXkpYi6ov5FcYDi1e";
    private static String SCHEMA_NAME = "gvt";
    private static String SCHEMA_VERSION = "1.0";
    private static String ISSUER_DID = "NcYxiDXkpYi6ov5FcYDi1e";
    private static String CRED_DEF_ID = "NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag";
    private static String REV_REG_ID = "NcYxiDXkpYi6ov5FcYDi1e:4:NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag:CL_ACCUM:TAG_1";
    private static String NO_REV_REG_ID = "None";

    private Credential credential() throws IOException {
        // note that encoding is not standardized by Indy except that 32-bit integers are encoded as themselves. IS-786
        // so Alex -> 12345 is an application choice while 25 -> 25 is not
        Map<String, AttributeValue> attr_values = new HashMap<>();
        attr_values.put("name", new AttributeValue("Alex", "12345"));
        attr_values.put("age", new AttributeValue("25", "25"));

        String json = "{\n" +
                "  \"schema_id\": \"NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0\",\n" +
                "  \"cred_def_id\": \"NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag\",\n" +
                "  \"rev_reg_id\": \"None\",\n" +
                "  \"values\": {\n" +
                "    \"name\": {\n" +
                "      \"raw\": \"Alex\",\n" +
                "      \"encoded\": \"1234\"\n" +
                "    },\n" +
                "    \"age\": {\n" +
                "      \"raw\": \"25\",\n" +
                "      \"encoded\": \"25\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"signature\": {\n" +
                "    \"p_credential\": {\n" +
                "      \"m_2\": \"0\",\n" +
                "      \"a\": \"0\",\n" +
                "      \"e\": \"0\",\n" +
                "      \"v\": \"0\"\n" +
                "    },\n" +
                "    \"r_credential\": null\n" +
                "  },\n" +
                "  \"signature_correctness_proof\": {\n" +
                "    \"se\": \"0\",\n" +
                "    \"c\": \"0\"\n" +
                "  },\n" +
                "  \"rev_reg\": null,\n" +
                "  \"witness\": null\n" +
                "}";

        ObjectMapper mapper = new ObjectMapper()
                //.setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        Credential credential = mapper.readValue(json, Credential.class);
        return credential;
    }

    @Test
    void buildCredentialTags() throws IOException {
        ProverService ps = new ProverService();
        Map<String, String> result = ps.buildCredentialTags(credential(), null);

        Map<String, String> expected_tags = new HashMap<>();
        expected_tags.put("schema_id", SCHEMA_ID);
        expected_tags.put("schema_issuer_did", SCHEMA_ISSUER_DID);
        expected_tags.put("schema_name", SCHEMA_NAME);
        expected_tags.put("schema_version", SCHEMA_VERSION);
        expected_tags.put("issuer_did", ISSUER_DID);
        expected_tags.put("cred_def_id", CRED_DEF_ID);
        expected_tags.put("rev_reg_id", NO_REV_REG_ID);
        expected_tags.put("attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER);
        expected_tags.put("attr::name::value", "Alex");
        expected_tags.put("attr::age::marker", ATTRIBUTE_EXISTENCE_MARKER);
        expected_tags.put("attr::age::value", "25");

        assertEquals(expected_tags, result);

        Set<String> tags = new HashSet<>();
        tags.add("name");
        CredentialAttrTagPolicy credentialAttrTagPolicy = new CredentialAttrTagPolicy(tags);

        result = ps.buildCredentialTags(credential(), credentialAttrTagPolicy);
        expected_tags = new HashMap<>();
        expected_tags.put("schema_id", SCHEMA_ID);
        expected_tags.put("schema_issuer_did", SCHEMA_ISSUER_DID);
        expected_tags.put("schema_name", SCHEMA_NAME);
        expected_tags.put("schema_version", SCHEMA_VERSION);
        expected_tags.put("issuer_did", ISSUER_DID);
        expected_tags.put("cred_def_id", CRED_DEF_ID);
        expected_tags.put("rev_reg_id", NO_REV_REG_ID);
        expected_tags.put("attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER);
        expected_tags.put("attr::name::value", "Alex");

        assertEquals(expected_tags, result);

        Credential credential = credential();
        credential.revocationRegistryId = new RevocationRegistryId("NcYxiDXkpYi6ov5FcYDi1e:4:NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag:CL_ACCUM:TAG_1");

        result = ps.buildCredentialTags(credential, null);
        expected_tags = new HashMap<>();
        expected_tags.put("schema_id", SCHEMA_ID);
        expected_tags.put("schema_issuer_did", SCHEMA_ISSUER_DID);
        expected_tags.put("schema_name", SCHEMA_NAME);
        expected_tags.put("schema_version", SCHEMA_VERSION);
        expected_tags.put("issuer_did", ISSUER_DID);
        expected_tags.put("cred_def_id", CRED_DEF_ID);
        expected_tags.put("rev_reg_id", REV_REG_ID);
        expected_tags.put("attr::name::marker", ATTRIBUTE_EXISTENCE_MARKER);
        expected_tags.put("attr::name::value", "Alex");
        expected_tags.put("attr::age::marker", ATTRIBUTE_EXISTENCE_MARKER);
        expected_tags.put("attr::age::value", "25");

        assertEquals(expected_tags, result);
     }
}