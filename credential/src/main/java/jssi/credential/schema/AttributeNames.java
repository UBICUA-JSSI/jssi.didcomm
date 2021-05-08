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

package jssi.credential.schema;

import jssi.credential.util.Validatable;
import jssi.credential.util.ValidateException;

import java.util.HashSet;

public class AttributeNames extends HashSet<String> implements Validatable {

    public static final int MAX_ATTRIBUTES_COUNT = 125;

    @Override
    public void validate() throws ValidateException {
        if(isEmpty()){
            throw new ValidateException("Empty list of Schema attributes has been passed");
        }

        if(size() > MAX_ATTRIBUTES_COUNT){
            throw new ValidateException(String.format("The number of Schema attributes %d cannot be greater than %d", size(), MAX_ATTRIBUTES_COUNT));
        }
    }
}
