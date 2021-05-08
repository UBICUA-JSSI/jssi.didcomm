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

import jssi.ursa.pair.PointG1;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Blinded Master Secret uses by Issuer in credential creation.
 */
public class BlindedCredentialSecrets {

    public BigInteger u = BigInteger.ZERO;
    public PointG1 ur;
    public List<String> hidden_attributes;
    public Map<String, BigInteger> committed_attributes;

    public BlindedCredentialSecrets(
            BigInteger u,
            PointG1 ur,
            List<String> hidden_attributes,
            Map<String, BigInteger> committed_attributes)
    {
        this.u = u;
        this.ur = ur;
        this.hidden_attributes = hidden_attributes;
        this.committed_attributes = committed_attributes;
    }
}
