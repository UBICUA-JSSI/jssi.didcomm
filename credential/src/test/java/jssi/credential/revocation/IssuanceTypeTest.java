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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class IssuanceTypeTest {

    @Test
    void isDefault_test() {
        IssuanceType type = IssuanceType.ISSUANCE_BY_DEFAULT;
        assertTrue(type.isDefault());
        type = IssuanceType.ISSUANCE_ON_DEMAND;
        assertTrue(!type.isDefault());
    }
}