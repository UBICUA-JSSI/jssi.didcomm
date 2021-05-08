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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

/// `Revocation Registry Delta` contains Accumulator changes.
/// Must be applied to `Revocation Registry`
public class RevocationRegistryDelta {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationRegistryDelta.class);

    Accumulator previous;
    Accumulator accumulator;
    List<Integer> issued;
    List<Integer> revoked;

    public RevocationRegistryDelta(Accumulator previous,
                                   Accumulator accumulator,
                                   List<Integer> issued,
                                   List<Integer> revoked) {
        this.previous = previous;
        this.accumulator = accumulator;
        this.issued = issued;
        this.revoked = revoked;

    }

    public static RevocationRegistryDelta fromParts(
            RevocationRegistry revocationRegistryFrom,
            RevocationRegistry revocationRegistryTo,
            List<Integer> issued,
            List<Integer> revoked) {

        return new RevocationRegistryDelta(revocationRegistryFrom == null ? null : revocationRegistryFrom.accumulator,
                revocationRegistryTo.accumulator,
                issued,
                revoked);
    }

    public void merge(RevocationRegistryDelta delta) {
        if (delta.previous == null || accumulator != delta.previous) {
            LOG.error("Deltas can not be merged.");
            return;
        }

        accumulator = delta.accumulator;

        issued.removeAll(delta.revoked);
        issued.addAll(delta.issued);
        issued = issued.stream().distinct().collect(Collectors.toList());

        revoked.removeAll(delta.issued);
        revoked.addAll(delta.revoked);
        revoked = revoked.stream().distinct().collect(Collectors.toList());
    }
}
