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

import java.util.ArrayList;
import java.util.List;

public class SimpleTailsAccessor implements RevocationTailsAccessor{

    private List<Tail> tails;

    private SimpleTailsAccessor(List<Tail> tails){
        this.tails = tails;
    }

    public static SimpleTailsAccessor create(RevocationTailsGenerator generator){
        List<Tail> tails = new ArrayList<>();

        Tail tail = generator.next();
        while(tail != null){
            tails.add(tail);
            tail = generator.next();
        }
        return new SimpleTailsAccessor(tails);
    }

    @Override
    public Tail access(int index) {
        return tails.get(index);
    }
}
