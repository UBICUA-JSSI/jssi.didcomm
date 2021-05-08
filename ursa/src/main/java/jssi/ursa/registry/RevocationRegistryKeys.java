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
import jssi.ursa.credential.CredentialRevocationPublicKey;
import jssi.ursa.pair.CryptoException;
import jssi.ursa.pair.GroupOrderElement;
import jssi.ursa.pair.Pair;
import jssi.ursa.util.Bytes;

public class RevocationRegistryKeys {

    private static final Logger LOG = LoggerFactory.getLogger(RevocationRegistryKeys.class);

    private RevocationPublicKey revocationPublicKey;
    private RevocationPrivateKey revocationPrivateKey;

    private RevocationRegistryKeys(RevocationPublicKey revocationPublicKey,
                                  RevocationPrivateKey revocationPrivateKey)
    {
        this.revocationPublicKey = revocationPublicKey;
        this.revocationPrivateKey = revocationPrivateKey;
    }

    public RevocationPublicKey getRevocationPublicKey() {
        return revocationPublicKey;
    }

    public RevocationPrivateKey getRevocationPrivateKey() {
        return revocationPrivateKey;
    }

    public static RevocationRegistryKeys create(
            CredentialRevocationPublicKey credentialRevocationPublicKey,
            int maxCredentials) throws CryptoException
    {

        LOG.debug("Create Revocation registry keys...");
        GroupOrderElement gamma = new GroupOrderElement();

        Pair z = Pair.pair(credentialRevocationPublicKey.g, credentialRevocationPublicKey.g_dash);
        GroupOrderElement pow = GroupOrderElement.fromBytes(Bytes.toBytes(maxCredentials + 1));
        pow = gamma.powmod(pow);
        z = z.pow(pow);
        return new RevocationRegistryKeys(new RevocationPublicKey(z), new RevocationPrivateKey(gamma));
    }
}
