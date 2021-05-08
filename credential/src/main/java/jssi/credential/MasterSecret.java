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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jssi.credential.util.Validatable;
import jssi.credential.util.ValidateException;

public class MasterSecret implements Validatable {

    public static final String TYPE = "Indy::MasterSecret";

    private jssi.ursa.credential.prover.MasterSecret value;

    @JsonCreator
    public MasterSecret(@JsonProperty("value") jssi.ursa.credential.prover.MasterSecret value){
        this.value = value;
    }

    @Override
    public String toString(){
        return String.format("Master secret: {ms %s}", value.ms);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        MasterSecret that = (MasterSecret) o;

        return value.ms.equals(that.value.ms);
    }

    public jssi.ursa.credential.prover.MasterSecret getValue() {
        return value;
    }

    @Override
    public void validate() throws ValidateException {

    }
}
