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

import java.util.List;
import java.util.stream.Collectors;

import static jssi.ursa.util.BigIntegers.asUnsignedByteArray;

public class PrimaryInitProof {

    PrimaryEqualInitProof eq_proof;
    List<PrimaryPredicateInequalityInitProof> ne_proofs;

    public PrimaryInitProof( PrimaryEqualInitProof eq_proof, List<PrimaryPredicateInequalityInitProof> ne_proofs){
        this.eq_proof = eq_proof;
        this.ne_proofs = ne_proofs;
    }

    public List<byte[]> toCList() {
        List<byte[]> c_list = eq_proof.toList();
        for(PrimaryPredicateInequalityInitProof ne_proof : ne_proofs) {
            List<byte[]> result = ne_proof.toList().stream()
                    .map(item -> asUnsignedByteArray(item))
                    .collect(Collectors.toList());
            c_list.addAll(result);
        }
       return c_list;
    }

    public List<byte[]> toTauList() {
        List<byte[]> tau_list = eq_proof.toTauList();
        for(PrimaryPredicateInequalityInitProof ne_proof : ne_proofs) {
            List<byte[]> result = ne_proof.toTauList().stream()
                    .map(item -> asUnsignedByteArray(item))
                    .collect(Collectors.toList());
            tau_list.addAll(result);
        }
        return tau_list;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PrimaryInitProof that = (PrimaryInitProof) o;

        if (!eq_proof.equals(that.eq_proof)) return false;
        return ne_proofs.equals(that.ne_proofs);
    }
}
