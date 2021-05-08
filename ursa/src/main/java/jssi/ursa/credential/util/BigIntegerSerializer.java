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

package jssi.ursa.credential.util;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.math.BigInteger;

public class BigIntegerSerializer extends StdSerializer<BigInteger> {

    public BigIntegerSerializer() {
        this(BigInteger.class);
    }

    public BigIntegerSerializer(Class<BigInteger> vc) {
        super(vc);
    }

    @Override
    public void serialize(BigInteger value, JsonGenerator generator, SerializerProvider provider) throws IOException {
        if(value == null){
            return;
        }
        generator.writeString(value.toString());
    }
}
