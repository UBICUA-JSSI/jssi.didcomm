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

import jssi.ursa.pair.GroupOrderElement;
import jssi.ursa.pair.PointG2;

public class RevocationTailsGenerator {

    private int size;
    private int current_index;
    private PointG2 g_dash;
    private GroupOrderElement gamma;

    public RevocationTailsGenerator(int maxCredentials, GroupOrderElement gamma, PointG2 g_dash){
        this.size = 2 * maxCredentials + 1; /* Unused 0th + valuable 1..L + unused (L+1)th + valuable (L+2)..(2L) */
        this.current_index = 0;
        this.gamma = gamma;
        this.g_dash = g_dash;
    }

    public int count() {
         return size - current_index;
    }

    public Tail next() {
        if (current_index >= size) {
            return null;
        }

        Tail tail = Tail.create(current_index, g_dash, gamma);
        current_index += 1;
        return tail;
    }
}
