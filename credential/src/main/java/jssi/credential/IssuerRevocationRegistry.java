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

package jssi.credential;

import jssi.credential.revocation.RevocationRegistryDefinitionValuePublicKeys;
import jssi.ursa.registry.RevocationPrivateKey;
import jssi.ursa.registry.RevocationRegistry;
import jssi.ursa.registry.RevocationTailsGenerator;

public class IssuerRevocationRegistry {

    RevocationRegistryDefinitionValuePublicKeys revocationRegistryDefinitionValuePublicKeys;
    RevocationPrivateKey revocationPrivateKey;
    RevocationRegistry revocationRegistry;
    RevocationTailsGenerator revocationTailsGenerator;

    public IssuerRevocationRegistry(
            RevocationRegistryDefinitionValuePublicKeys revocationRegistryDefinitionValuePublicKeys,
            RevocationPrivateKey revocationPrivateKey,
            RevocationRegistry revocationRegistry,
            RevocationTailsGenerator revocationTailsGenerator)
    {
        this.revocationRegistryDefinitionValuePublicKeys = revocationRegistryDefinitionValuePublicKeys;
        this.revocationPrivateKey = revocationPrivateKey;
        this.revocationRegistry = revocationRegistry;
        this.revocationTailsGenerator = revocationTailsGenerator;
    }
}
