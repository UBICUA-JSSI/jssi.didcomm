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

package jssi.credential.revocation;

import jssi.credential.util.Validatable;
import jssi.credential.util.ValidateException;

public class RevocationRegistryConfig implements Validatable {

    public IssuanceType issuance_type;
    public int max_cred_num;

    public RevocationRegistryConfig(IssuanceType issuance_type, int max_cred_num){
        this.issuance_type = issuance_type;
        this.max_cred_num = max_cred_num;
    }

    @Override
    public void validate() throws ValidateException {
        if(max_cred_num <= 0){
            throw new ValidateException("RevocationRegistryConfig validation failed: `max_cred_num` must be greater than 0");
        }
    }
}
