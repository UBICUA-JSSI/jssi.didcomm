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

import jssi.ursa.credential.issuer.Issuer;
import jssi.ursa.credential.issuer.IssuerEmulator;
import jssi.ursa.pair.CryptoException;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class FileTailsAccessorTest {

    private static final String TAILS_DIR = "C:\\IntelliJ\\projects\\";
    Path path = Paths.get(TAILS_DIR, "tails");

    private FileTailsAccessor getFileTailsAccessor() throws CryptoException {

        IssuerEmulator issuer = new IssuerEmulator();

        RevocationRegistryDefinition revocationRegistryDefinition = Issuer.createRevocationRegistryDefinition(
                issuer.getCredentialPublicKey(),
                10,
                true);

        return FileTailsAccessor.create(path, revocationRegistryDefinition.revocationTailsGenerator);
    }

    @Test
    void access_test() throws CryptoException {
        FileTailsAccessor accessor = getFileTailsAccessor();
        Tail tail = accessor.access(1);
        assertNotNull(tail);
    }
}