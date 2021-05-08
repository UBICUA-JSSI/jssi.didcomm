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

package jssi.ursa.registry;

import jssi.ursa.pair.PointG2;

import java.util.ArrayList;
import java.util.List;

public class Witness {

    public PointG2 omega;

    private Witness(PointG2 omega){
        this.omega = omega;
    }

    public static <E extends RevocationTailsAccessor> Witness create(
            int revocationIndex,
            int maxCredentials,
            boolean isDefault,
            RevocationRegistryDelta revocationRegistryDelta,
            E revocationTailsAccessor)
    {
        PointG2 omega = PointG2.infinity();
        List<Integer> issued = new ArrayList<>();

        if(isDefault){
            for(int i = 1; i < maxCredentials + 1; i++){
                issued.add(i);
            }
            // TODO
            if(revocationRegistryDelta != null) {
                for (int j : revocationRegistryDelta.revoked) {
                    issued.remove(Integer.valueOf(j));
                }
            }
        } else {
            issued.addAll(revocationRegistryDelta.issued);
        }

        issued.remove(Integer.valueOf(revocationIndex));

        for(int j : issued) {
            int index = maxCredentials + 1 - j + revocationIndex;
            Tail tail = revocationTailsAccessor.access(index);
            omega = omega.add(tail);
        }
        return new Witness(omega);
    }

    public <E extends RevocationTailsAccessor> void update(
            int revocationIndex,
            int maxCredentials,
            RevocationRegistryDelta revocationRegistryDelta,
            E revocationTailsAccessor)
    {
        PointG2 omega_denom = PointG2.infinity();
        for (int j : revocationRegistryDelta.revoked) {
            if (revocationIndex == j) {
                continue;
            }

            int index = maxCredentials + 1 - j + revocationIndex;
            Tail tail = revocationTailsAccessor.access(index);
            omega_denom = omega_denom.add(tail);
        }

        PointG2 omega_num = PointG2.infinity();
        for (int j : revocationRegistryDelta.issued) {
            if (revocationIndex == j) {
                continue;
            }

            int index = maxCredentials + 1 - j + revocationIndex;
            Tail tail = revocationTailsAccessor.access(index);
            omega_num = omega_num.add(tail);
        }

        this.omega = this.omega.add(omega_num.sub(omega_denom));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Witness witness = (Witness) o;

        return omega.equals(witness.omega);
    }
}
