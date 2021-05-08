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

import java.math.BigInteger;

public class PrimaryCredentialSignature {

    @JsonSerialize(using = ToStringSerializer.class) public BigInteger m_2;
    @JsonSerialize(using = ToStringSerializer.class) public BigInteger a;
    @JsonSerialize(using = ToStringSerializer.class) public BigInteger e;
    @JsonSerialize(using = ToStringSerializer.class) public BigInteger v;

    @JsonCreator
    public PrimaryCredentialSignature(
            @JsonProperty("m_2") BigInteger m_2,
            @JsonProperty("a") BigInteger a,
            @JsonProperty("e") BigInteger e,
            @JsonProperty("v") BigInteger v)
    {
        this.m_2 = m_2;
        this.a = a;
        this.e = e;
        this.v = v;
    }

}
