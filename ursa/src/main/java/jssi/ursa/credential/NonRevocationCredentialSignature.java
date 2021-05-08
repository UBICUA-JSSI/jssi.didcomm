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

import jssi.ursa.pair.GroupOrderElement;
import jssi.ursa.pair.PointG1;
import jssi.ursa.registry.WitnessSignature;

public class NonRevocationCredentialSignature {

    public PointG1 sigma;
    public GroupOrderElement c;
    public GroupOrderElement vr_prime_prime;
    public WitnessSignature witness_signature;
    public PointG1 g_i;
    int index;
    public GroupOrderElement m2;

    public NonRevocationCredentialSignature(
            PointG1 sigma,
            GroupOrderElement c,
            GroupOrderElement vr_prime_prime,
            WitnessSignature witness_signature,
            PointG1 g_i,
            int index,
            GroupOrderElement m2)
    {
        this.sigma = sigma;
        this.c = c;
        this.vr_prime_prime = vr_prime_prime;
        this.witness_signature = witness_signature;
        this.g_i = g_i;
        this.index = index;
        this.m2 = m2;
    }
}
