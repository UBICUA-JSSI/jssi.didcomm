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

public class CredentialValue {

    public static enum Type{
        KNOWN,
        HIDDEN,
        COMMITMENT
    }

    public BigInteger value;
    public BigInteger blinding;
    public Type type;

    public CredentialValue(Type type, BigInteger value, BigInteger blinding){
        this.type = type;
        this.value = value;
        this.blinding = blinding;
    }

    public CredentialValue(Type type, BigInteger value){
        this(type, value, null);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CredentialValue that = (CredentialValue) o;

        if (value != null ? !value.equals(that.value) : that.value != null) return false;
        if (blinding != null ? !blinding.equals(that.blinding) : that.blinding != null) return false;
        return type == that.type;
    }
}
