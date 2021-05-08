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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.pair.GroupOrderElement;
import jssi.ursa.pair.PointG1;
import jssi.ursa.pair.PointG2;

public class CredentialRevocationKeys {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialRevocationKeys.class);

    private CredentialRevocationPublicKey credentialRevocationPublicKey;
    private CredentialRevocationPrivateKey credentialRevocationPrivateKey;

    private CredentialRevocationKeys(CredentialRevocationPublicKey credentialRevocationPublicKey, CredentialRevocationPrivateKey credentialRevocationPrivateKey){
        this.credentialRevocationPublicKey = credentialRevocationPublicKey;
        this.credentialRevocationPrivateKey = credentialRevocationPrivateKey;
    }

    public CredentialRevocationKeys(){
        this(null, null);
    }

    public CredentialRevocationPublicKey getCredentialRevocationPublicKey() {
        return credentialRevocationPublicKey;
    }

    public CredentialRevocationPrivateKey getCredentialRevocationPrivateKey() {
        return credentialRevocationPrivateKey;
    }

    public static CredentialRevocationKeys create(){

        LOG.debug("Create Credential revocation keys...");
        PointG1 h = new PointG1();
        PointG1 h0 = new PointG1();
        PointG1 h1 = new PointG1();
        PointG1 h2 = new PointG1();
        PointG1 h_tilde = new PointG1();
        PointG1 g = new PointG1();

        PointG2 u = new PointG2();
        PointG2 h_cap = new PointG2();

        GroupOrderElement x = new GroupOrderElement();
        GroupOrderElement sk = new GroupOrderElement();
        PointG2 g_dash = new PointG2();

        PointG1 pk = g.mul(sk);
        PointG2 y = h_cap.mul(x);

        CredentialRevocationPublicKey revocationPublicKey = new CredentialRevocationPublicKey(g, g_dash, h, h0, h1, h2, h_tilde, h_cap, u, pk, y);
        CredentialRevocationPrivateKey revocationPrivateKey = new CredentialRevocationPrivateKey(x, sk);

        return new CredentialRevocationKeys(revocationPublicKey, revocationPrivateKey);
    }
}
