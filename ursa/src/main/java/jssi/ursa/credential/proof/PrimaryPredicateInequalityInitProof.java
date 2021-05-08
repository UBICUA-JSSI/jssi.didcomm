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
import java.util.List;
import java.util.Map;

public class PrimaryPredicateInequalityInitProof {

    List<BigInteger> c_list;
    List<BigInteger>  tau_list;
    Map<String, BigInteger> u;
    Map<String, BigInteger> u_tilde;
    Map<String, BigInteger> r;
    Map<String, BigInteger> r_tilde;
    BigInteger alpha_tilde;
    Predicate predicate;
    Map<String, BigInteger> t;

    public PrimaryPredicateInequalityInitProof(
            List<BigInteger> c_list,
            List<BigInteger>  tau_list,
            Map<String, BigInteger> u,
            Map<String, BigInteger> u_tilde,
            Map<String, BigInteger> r,
            Map<String, BigInteger> r_tilde,
            BigInteger alpha_tilde,
            Predicate predicate,
            Map<String, BigInteger> t)
    {
        this.c_list = c_list;
        this.tau_list = tau_list;
        this.u = u;
        this.u_tilde = u_tilde;
        this.r = r;
        this.r_tilde = r_tilde;
        this.alpha_tilde = alpha_tilde;
        this.predicate = predicate;
        this.t = t;
    }

    public List<BigInteger> toList() {
        return c_list;
    }

    public List<BigInteger> toTauList()  {
        return tau_list;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryPredicateInequalityInitProof that = (PrimaryPredicateInequalityInitProof) o;

        if (!c_list.equals(that.c_list)) return false;
        if (!tau_list.equals(that.tau_list)) return false;
        if (!u.equals(that.u)) return false;
        if (!u_tilde.equals(that.u_tilde)) return false;
        if (!r.equals(that.r)) return false;
        if (!r_tilde.equals(that.r_tilde)) return false;
        if (!alpha_tilde.equals(that.alpha_tilde)) return false;
        if (!predicate.equals(that.predicate)) return false;
        return t.equals(that.t);
    }
}
