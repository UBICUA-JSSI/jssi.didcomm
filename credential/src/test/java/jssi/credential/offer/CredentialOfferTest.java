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

package jssi.credential.offer;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.junit.jupiter.api.Test;
import jssi.ursa.credential.util.BigIntegerSerializer;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CredentialOfferTest {

    @Test
    void json_test() throws IOException {

        ObjectMapper mapper = new ObjectMapper()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

        SimpleModule module = new SimpleModule("BigIntegerSerializer", new Version(1, 0, 0, null, null, null));
        module.addSerializer(BigInteger.class, new BigIntegerSerializer());
        mapper.registerModule(module);

        InputStream is =  getClass().getClassLoader().getResourceAsStream("offer/credential_offer.json");

        CredentialOffer credentialOffer = mapper.readValue(is, CredentialOffer.class);
        String result = mapper.writeValueAsString(credentialOffer);
        assertNotNull(credentialOffer);

    }

}