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

import org.junit.jupiter.api.Test;
import jssi.credential.proof.PredicateInfo;
import jssi.credential.proof.PredicateTypes;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProverServiceTest2 {

    private PredicateInfo predicate_info() {
        return new PredicateInfo(
                "age",
                PredicateTypes.GE,
                8,
                null,
                null);
    }

    @Test
    void attributeSatisfyPredicate() {
        ProverService ps = new ProverService();
        boolean result = ps.attributeSatisfyPredicate(predicate_info(), "10");
        assertTrue(result);

        result = ps.attributeSatisfyPredicate(predicate_info(), "5");
        assertTrue(!result);

        assertThrows(NumberFormatException.class, () ->{
            ps.attributeSatisfyPredicate(predicate_info(), "string");
        });
     }
}