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

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

import static jssi.ursa.credential.CredentialValue.Type.HIDDEN;
import static jssi.ursa.credential.CredentialValue.Type.KNOWN;

/// represents credential attributes values map.
///
// # Example
/// ```
///
/// CredentialValuesBuilder builder = CredentialValues.builder();
/// builder.addKnown("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103");
/// builder.addKnown("name", "1139481716457488690172217916278103335");
/// CredentialValues values = builder.build();
/// ```
public class CredentialValues {

    private final Map<String, CredentialValue> values;

    private CredentialValues(Map<String, CredentialValue> values){
        this.values = values;
    }

    public static CredentialValuesBuilder builder(){
        return new CredentialValuesBuilder();
    }

    public static class CredentialValuesBuilder {

        Map<String, CredentialValue> values = new LinkedHashMap<>();

        public void addKnown(String name, BigInteger value){
            values.put(name, new CredentialValue(KNOWN, value));
        }

        public void addKnown(String name, String value){
            values.put(name, new CredentialValue(KNOWN, new BigInteger(value, 10)));
        }

        public void addHidden(String name, BigInteger value){
            values.put(name, new CredentialValue(HIDDEN, value));
        }

        public void addHidden(String name, String value){
            values.put(name, new CredentialValue(HIDDEN, new BigInteger(value, 10)));
        }

        public void addCommitment(String name, BigInteger value, BigInteger blinding){
            values.put(name, new CredentialValue(HIDDEN, value, blinding));
        }

        public void addCommitment(String name, String value, String blinding){
            values.put(name, new CredentialValue(HIDDEN, new BigInteger(value, 10), new BigInteger(blinding, 10)));
        }

        public CredentialValues build(){
            return new CredentialValues(values);
        }
    }

    public Map<String, CredentialValue> getValues() {
        return values;
    }
}
