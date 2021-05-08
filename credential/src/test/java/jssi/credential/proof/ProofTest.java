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

package jssi.credential.proof;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import org.junit.jupiter.api.Test;
import jssi.ursa.credential.util.ByteArraySerializer;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ProofTest {

    @Test
    void json_test() throws IOException, URISyntaxException {

        SimpleModule module = new SimpleModule();
        module.addSerializer(BigInteger.class, new ToStringSerializer());
        module.addSerializer(new ByteArraySerializer());

        ObjectMapper mapper = new ObjectMapper()
                .registerModule(module)
                .enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

        InputStream is =  getClass().getClassLoader().getResourceAsStream("proof/proof1.json");
        Proof proof = mapper.readValue(is, Proof.class);
        String result = mapper.writeValueAsString(proof);
        assertNotNull(proof);

        is =  getClass().getClassLoader().getResourceAsStream("proof/proof2.json");
        proof = mapper.readValue(is, Proof.class);
        result = mapper.writeValueAsString(proof);
        assertNotNull(proof);
    }

}