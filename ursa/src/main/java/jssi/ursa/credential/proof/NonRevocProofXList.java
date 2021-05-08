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

package jssi.ursa.credential.proof;

import jssi.ursa.pair.GroupOrderElement;

import java.util.ArrayList;
import java.util.List;

public class NonRevocProofXList {
    public GroupOrderElement rho;
    public GroupOrderElement r;
    public GroupOrderElement r_prime;
    public GroupOrderElement r_prime_prime;
    public GroupOrderElement r_prime_prime_prime;
    public GroupOrderElement o;
    public GroupOrderElement o_prime;
    public GroupOrderElement m;
    public GroupOrderElement m_prime;
    public GroupOrderElement t;
    public GroupOrderElement t_prime;
    public GroupOrderElement m2;
    public GroupOrderElement s;
    public GroupOrderElement c;

    public NonRevocProofXList(
            GroupOrderElement rho,
            GroupOrderElement r,
            GroupOrderElement r_prime,
            GroupOrderElement r_prime_prime,
            GroupOrderElement r_prime_prime_prime,
            GroupOrderElement o,
            GroupOrderElement o_prime,
            GroupOrderElement m,
            GroupOrderElement m_prime,
            GroupOrderElement t,
            GroupOrderElement t_prime,
            GroupOrderElement m2,
            GroupOrderElement s,
            GroupOrderElement c)
    {
        this.rho = rho;
        this.r = r;
        this.r_prime = r_prime;
        this.r_prime_prime = r_prime_prime;
        this.r_prime_prime_prime = r_prime_prime_prime;
        this.o = o;
        this.o_prime = o_prime;
        this.m = m;
        this.m_prime = m_prime;
        this.t = t;
        this.t_prime = t_prime;
        this.m2 = m2;
        this.s = s;
        this.c = c;
    }

    public List<GroupOrderElement> toList()  {
        List<GroupOrderElement> result = new ArrayList<>();
        result.add(rho);
        result.add(o);
        result.add(c);
        result.add(o_prime);
        result.add(m);
        result.add(m_prime);
        result.add(t);
        result.add(t_prime);
        result.add(m2);
        result.add(s);
        result.add(r);
        result.add(r_prime);
        result.add(r_prime_prime);
        result.add(r_prime_prime_prime);
        return result;
    }

    public static NonRevocProofXList fromList(List<GroupOrderElement> seq) {
        return new NonRevocProofXList(
                seq.get(0),
                seq.get(10),
                seq.get(11),
                seq.get(12),
                seq.get(13),
                seq.get(1),
                seq.get(3),
                seq.get(4),
                seq.get(5),
                seq.get(6),
                seq.get(7),
                seq.get(8),
                seq.get(9),
                seq.get(2));
    }
}
