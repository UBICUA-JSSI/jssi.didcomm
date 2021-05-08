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
 * Issuer Public Key contains 2 internal parts.
 * One for signing primary credentials and second for signing non-revocation credentials.
 * These keys are used to proof that credential was issued and doesn’t revoked by this issuer.
 * Issuer keys have global identifier that must be known to all parties.
 */
public class CredentialPublicKey {

    public CredentialPrimaryPublicKey p_key;
    public CredentialRevocationPublicKey r_key;

    public CredentialPublicKey(CredentialPrimaryPublicKey p_key, CredentialRevocationPublicKey r_key){
        this.p_key = p_key;
        this.r_key = r_key;
    }
}
