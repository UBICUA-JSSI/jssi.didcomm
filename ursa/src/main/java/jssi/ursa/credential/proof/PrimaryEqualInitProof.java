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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static jssi.ursa.util.BigIntegers.asUnsignedByteArray;

public class PrimaryEqualInitProof {

    public BigInteger a_prime;
    public BigInteger t;
    public BigInteger e_tilde;
    public BigInteger  e_prime;
    public BigInteger v_tilde;
    public BigInteger v_prime;
    public Map<String, BigInteger > m_tilde;
    public BigInteger m2_tilde;
    public BigInteger m2;

    public PrimaryEqualInitProof(
            BigInteger a_prime,
            BigInteger t,
            BigInteger e_tilde,
            BigInteger e_prime,
            BigInteger v_tilde,
            BigInteger v_prime,
            Map<String, BigInteger> m_tilde,
            BigInteger m2_tilde,
            BigInteger m2)
    {
        this.a_prime = a_prime;
        this.t = t;
        this.e_tilde = e_tilde;
        this.e_prime = e_prime;
        this.v_tilde = v_tilde;
        this.v_prime = v_prime;
        this.m_tilde = m_tilde;
        this.m2_tilde = m2_tilde;
        this.m2 = m2;
    }

    public List<byte[]> toList() {
        List<byte[]> result = new ArrayList<>();
        result.add(asUnsignedByteArray(a_prime));
        return result;
    }

    public List<byte[]> toTauList() {
        List<byte[]> result = new ArrayList<>();
        result.add(asUnsignedByteArray(t));
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryEqualInitProof that = (PrimaryEqualInitProof) o;

        if (!a_prime.equals(that.a_prime)) return false;
        if (!t.equals(that.t)) return false;
        if (!e_tilde.equals(that.e_tilde)) return false;
        if (!e_prime.equals(that.e_prime)) return false;
        if (!v_tilde.equals(that.v_tilde)) return false;
        if (!v_prime.equals(that.v_prime)) return false;
        if (!m_tilde.equals(that.m_tilde)) return false;
        if (!m2_tilde.equals(that.m2_tilde)) return false;
        return m2.equals(that.m2);
    }
}
