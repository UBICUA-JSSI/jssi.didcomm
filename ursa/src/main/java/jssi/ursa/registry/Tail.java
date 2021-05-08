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
import jssi.ursa.pair.GroupOrderElement;
import jssi.ursa.pair.PointG2;
import jssi.ursa.util.Integers;

public class Tail extends PointG2 {

    public Tail(PointG2 pointG2) {
        super(pointG2);
    }

    public Tail(){
        super();
    }

    public static Tail create(int index, PointG2 g_dash, GroupOrderElement gamma) {
        byte[] i_bytes = Integers.toBytes(index);
        try {
            GroupOrderElement pow = new GroupOrderElement().fromBytes(i_bytes);
            pow = gamma.powmod(pow);
            return new Tail(g_dash.mul(pow));
        } catch (CryptoException e){
            return new Tail();
        }
    }
}
