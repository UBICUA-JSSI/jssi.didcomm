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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jssi.ursa.credential.CredentialHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.credential.CredentialPrimaryPublicKey;
import jssi.ursa.credential.CredentialValue;
import jssi.ursa.credential.CredentialValues;
import jssi.ursa.credential.util.BigNumber;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static jssi.ursa.credential.util.BigNumber.*;

public class PrimaryPredicateInequalityProof {

    private static final Logger LOG = LoggerFactory.getLogger(PrimaryPredicateInequalityProof.class);

    public Map<String, BigInteger> u;
    public Map<String, BigInteger> r;
    public BigInteger mj;
    public BigInteger alpha;
    public Map<String, BigInteger> t;
    public Predicate predicate;

    @JsonCreator
    public PrimaryPredicateInequalityProof(
            @JsonProperty("u") Map<String, BigInteger> u,
            @JsonProperty("r") Map<String, BigInteger> r,
            @JsonProperty("mj") BigInteger mj,
            @JsonProperty("alpha") BigInteger alpha,
            @JsonProperty("t") Map<String, BigInteger> t,
            @JsonProperty("predicate") Predicate predicate)
    {
        this.u = u;
        this.r = r;
        this.mj = mj;
        this.alpha = alpha;
        this.t = t;
        this.predicate = predicate;
    }

    public static PrimaryPredicateInequalityInitProof init(
            CredentialPrimaryPublicKey credentialPrimaryPublicKey,
            Map<String, BigInteger> m_tilde,
            CredentialValues credentialValues,
            Predicate predicate)
    {

        CredentialValue attr_value = credentialValues.getValues().get(predicate.attr_name);
        if(attr_value == null){
            LOG.error(String.format("Value by key '%s' not found in cred_values", predicate.attr_name));
            return null;
        }

        int value = attr_value.value.intValue();
        int delta = predicate.getDelta(value);

        if (delta < 0) {
            LOG.error("Predicate is not satisfied");
            return null;
        }

        Map<String, BigInteger> u = BigNumber.lagrange(delta);

        Map<String, BigInteger> r = new HashMap<>();
        Map<String, BigInteger> t = new HashMap<>();
        List<BigInteger> c_list = new ArrayList<>();

        for( int i = 0; i < ITERATION; i++) {

            BigInteger cur_u = u.get(String.valueOf(i));
            if (cur_u == null) {
                LOG.error(String.format("Value by key '%d' not found in u1", i));
                return null;
            }

            BigInteger cur_r = BigNumber.random(LARGE_VPRIME);
            cur_r = new BigInteger("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290", 10);
            BigInteger cut_t = CredentialHelper.getPedersenCommitment(
                    credentialPrimaryPublicKey.z,
                    cur_u,
                    credentialPrimaryPublicKey.s,
                    cur_r,
                    credentialPrimaryPublicKey.n);

            r.put(String.valueOf(i), cur_r);
            t.put(String.valueOf(i), cut_t);
            c_list.add(cut_t);
        }

        BigInteger r_delta = BigNumber.random(LARGE_VPRIME);
        r_delta = new BigInteger("35131625843806290832574870589259287147303302356085937450138681169270844305658441640899780357851554390281352797472151859633451190372182905767740276000477099644043795107449461869975792759973231599572009337886283219344284767785705740629929916685684025616389621432096690068102576167647117576924865030253290356476886389376786906469624913865400296221181743871195998667521041628188272244376790322856843509187067488962831880868979749045372839549034465343690176440012266969614156191820420452812733264350018673445974099278245215963827842041818557926829011513408602244298030173493359464182527821314118075880620818817455331127028576670474022443879858290", 10);

        BigInteger t_delta = CredentialHelper.getPedersenCommitment(
                credentialPrimaryPublicKey.z,
                new BigInteger(String.valueOf(delta)),
                credentialPrimaryPublicKey.s,
                r_delta,
                credentialPrimaryPublicKey.n);

        r.put("DELTA", r_delta);
        t.put("DELTA", t_delta);
        c_list.add(t_delta);

        Map<String, BigInteger> u_tilde = new HashMap<>();
        Map<String, BigInteger> r_tilde = new HashMap<>();

        for(int i = 0; i < ITERATION; i++) {
            BigInteger large_utilde = BigNumber.random(LARGE_UTILDE);
            large_utilde = new BigInteger("6461691768834933403326572830814516653957231030793837560544354737855803497655300429843454445497126567767486684087006218691084619904526729989680526652503377438786587511370042964338", 10);
            u_tilde.put(String.valueOf(i), large_utilde);
            BigInteger large_rtilde = BigNumber.random(LARGE_RTILDE);
            large_rtilde = new BigInteger("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847", 10);
            r_tilde.put(String.valueOf(i),  large_rtilde);
        }

        BigInteger large_rtilde = BigNumber.random(LARGE_RTILDE);
        large_rtilde = new BigInteger("7575191721496255329790454166600075461811327744716122725414003704363002865687003988444075479817517968742651133011723131465916075452356777073568785406106174349810313776328792235352103470770562831584011847", 10);
        r_tilde.put("DELTA", large_rtilde);

        BigInteger alpha_tilde = BigNumber.random(LARGE_ALPHATILDE);
        alpha_tilde = new BigInteger("15019832071918025992746443764672619814038193111378331515587108416842661492145380306078894142589602719572721868876278167686578705125701790763532708415180504799241968357487349133908918935916667492626745934151420791943681376124817051308074507483664691464171654649868050938558535412658082031636255658721308264295197092495486870266555635348911182100181878388728256154149188718706253259396012667950509304959158288841789791483411208523521415447630365867367726300467842829858413745535144815825801952910447948288047749122728907853947789264574578039991615261320141035427325207080621563365816477359968627596441227854436137047681372373555472236147836722255880181214889123172703767379416198854131024048095499109158532300492176958443747616386425935907770015072924926418668194296922541290395990933578000312885508514814484100785527174742772860178035596639", 10);

        BigInteger mj = m_tilde.get(predicate.attr_name);
        if (mj == null) {
            LOG.error(String.format("Value by key '%s' not found in eq_proof.mtilde", predicate.attr_name));
            return null;
        }


        List<BigInteger> tau_list = CredentialHelper.calc_tne(
                credentialPrimaryPublicKey,
                u_tilde,
                r_tilde,
                mj,
                alpha_tilde,
                t,
                predicate.isLess());

        return new  PrimaryPredicateInequalityInitProof(
                c_list,
                tau_list,
                u,
                u_tilde,
                r,
                r_tilde,
                alpha_tilde,
                predicate,
                t);
    }

    public static PrimaryPredicateInequalityProof finalize(
            BigInteger c_h,
            PrimaryPredicateInequalityInitProof primaryPredicateInequalityInitProof,
            PrimaryEqualProof eq_proof)
    {

        Map<String, BigInteger> u = new HashMap<>();
        Map<String, BigInteger> r = new HashMap<>();
        BigInteger urproduct = BigInteger.ZERO;

        for(int i = 0; i < ITERATION; i++) {
            BigInteger cur_u_tilde = primaryPredicateInequalityInitProof.u_tilde.get(String.valueOf(i));
            BigInteger cur_u = primaryPredicateInequalityInitProof.u.get(String.valueOf(i));
            BigInteger cur_r_tilde = primaryPredicateInequalityInitProof.r_tilde.get(String.valueOf(i));
            BigInteger cur_r = primaryPredicateInequalityInitProof.r.get(String.valueOf(i));

            BigInteger new_u = c_h.multiply(cur_u).add(cur_u_tilde);
            BigInteger new_r = c_h.multiply(cur_r).add(cur_r_tilde);

            u.put(String.valueOf(i), new_u);
            r.put(String.valueOf(i), new_r);

            urproduct = cur_u.multiply(cur_r).add(urproduct);

            BigInteger cur_r_tilde_delta = primaryPredicateInequalityInitProof.r_tilde.get("DELTA");
            BigInteger new_delta = c_h.multiply(primaryPredicateInequalityInitProof.r.get("DELTA")).add(cur_r_tilde_delta);

            r.put("DELTA", new_delta);
        }

        BigInteger alpha = primaryPredicateInequalityInitProof.r.get("DELTA")
                .subtract(urproduct)
                .multiply(c_h)
                .add(primaryPredicateInequalityInitProof.alpha_tilde);

        return new PrimaryPredicateInequalityProof(
                u,
                r,
                eq_proof.m.get(primaryPredicateInequalityInitProof.predicate.attr_name),
                alpha,
                primaryPredicateInequalityInitProof.t,
                primaryPredicateInequalityInitProof.predicate);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryPredicateInequalityProof that = (PrimaryPredicateInequalityProof) o;

        if (!u.equals(that.u)) return false;
        if (!r.equals(that.r)) return false;
        if (!mj.equals(that.mj)) return false;
        if (!alpha.equals(that.alpha)) return false;
        if (!t.equals(that.t)) return false;
        return predicate.equals(that.predicate);
    }
}
