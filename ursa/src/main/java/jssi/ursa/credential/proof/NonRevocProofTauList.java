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

import jssi.ursa.pair.Pair;
import jssi.ursa.pair.PointG1;

import java.util.ArrayList;
import java.util.List;

public class NonRevocProofTauList {
    public PointG1 t1;
    public PointG1 t2;
    public Pair t3;
    public Pair t4;
    public PointG1 t5;
    public PointG1 t6;
    public Pair t7;
    public Pair t8;

    public NonRevocProofTauList(
            PointG1 t1,
            PointG1 t2,
            Pair t3,
            Pair t4,
            PointG1 t5,
            PointG1 t6,
            Pair t7,
            Pair t8)
    {
        this.t1 = t1;
        this.t2 = t2;
        this.t3 = t3;
        this.t4 = t4;
        this.t5 = t5;
        this.t6 = t6;
        this.t7 = t7;
        this.t8 = t8;
    }

    public List<byte[]> toList() {
        List<byte[]> result = new ArrayList<>();
        result.add(t1.toBytes());
        result.add(t2.toBytes());
        result.add(t3.toBytes());
        result.add(t4.toBytes());
        result.add(t5.toBytes());
        result.add(t6.toBytes());
        result.add(t7.toBytes());
        result.add(t8.toBytes());
        return result;
    }
}
