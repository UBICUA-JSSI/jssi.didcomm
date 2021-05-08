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

import jssi.ursa.pair.CryptoException;
import jssi.ursa.pair.PointG2;

public class Accumulator extends PointG2 {

    public Accumulator(PointG2 point) {
        super(point);
    }

    public Accumulator(){
        super();
    }

    public static Accumulator fromHex(String[] hex){
        try {
            return new Accumulator(PointG2.fromHex(hex));
        } catch (CryptoException e){
            return null;
        }
    }

    public Accumulator sub(Tail tail){
        return new Accumulator(super.sub(tail));
    }

    public Accumulator add(Tail tail){
        return new Accumulator(super.add(tail));
    }

}
