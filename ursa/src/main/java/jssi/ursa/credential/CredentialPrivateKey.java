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


/**
 * Issuer Private Key`: contains 2 internal parts.
 * One for signing primary credentials and second for signing non-revocation credentials.
 */
public class CredentialPrivateKey {
    public CredentialPrimaryPrivateKey p_key;
    public CredentialRevocationPrivateKey r_key;

    public CredentialPrivateKey(CredentialPrimaryPrivateKey p_key, CredentialRevocationPrivateKey r_key){
        this.p_key = p_key;
        this.r_key = r_key;
    }
}
