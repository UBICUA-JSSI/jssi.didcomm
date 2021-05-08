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

import jssi.ursa.pair.PointG1;
import jssi.ursa.pair.PointG2;

import java.util.ArrayList;
import java.util.List;

public class NonRevocProofCList {
    public PointG1 e;
    public PointG1 d;
    public PointG1 a;
    public PointG1 g;
    public PointG2 w;
    public PointG2 s;
    public PointG2 u;

    public NonRevocProofCList(
            PointG1 e,
            PointG1 d,
            PointG1 a,
            PointG1 g,
            PointG2 w,
            PointG2 s,
            PointG2 u)
    {
        this.e = e;
        this.d = d;
        this.a = a;
        this.g = g;
        this.w = w;
        this.s = s;
        this.u = u;
    }

    public List<byte[]> toList() {
        List<byte[]> result = new ArrayList<>();
        result.add(e.toBytes());
        result.add(d.toBytes());
        result.add(a.toBytes());
        result.add(g.toBytes());
        result.add(w.toBytes());
        result.add(s.toBytes());
        result.add(u.toBytes());
        return result;
    }
}
