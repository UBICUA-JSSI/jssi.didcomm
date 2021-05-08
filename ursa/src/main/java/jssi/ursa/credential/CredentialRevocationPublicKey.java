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

package jssi.ursa.credential;

import jssi.ursa.pair.PointG1;
import jssi.ursa.pair.PointG2;

public class CredentialRevocationPublicKey {

    public PointG1 g;
    public PointG2 g_dash;
    public PointG1 h;
    public PointG1 h0;
    public PointG1 h1;
    public PointG1 h2;
    public PointG1 h_tilde;
    public PointG2 h_cap;
    public PointG2 u;
    public PointG1 pk;
    public PointG2 y;

    public CredentialRevocationPublicKey(
            PointG1 g,
            PointG2 g_dash,
            PointG1 h,
            PointG1 h0,
            PointG1 h1,
            PointG1 h2,
            PointG1 h_tilde,
            PointG2 h_cap,
            PointG2 u,
            PointG1 pk,
            PointG2 y)
    {
        this.g = g;
        this.g_dash = g_dash;
        this.h = h;
        this.h0 = h0;
        this.h1 = h1;
        this.h2 = h2;
        this.h_tilde = h_tilde;
        this.h_cap = h_cap;
        this.u = u;
        this.pk = pk;
        this.y = y;
    }
}
