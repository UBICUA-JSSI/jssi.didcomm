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

public class Filter {

    String schema_id;
    String schema_issuer_did;
    String schema_name;
    String schema_version;
    String issuer_did;
    String cred_def_id;

    public Filter(
            String schema_id,
            String schema_issuer_did,
            String schema_name,
            String schema_version,
            String issuer_did,
            String cred_def_id)
    {
        this.schema_id = schema_id;
        this.schema_issuer_did = schema_issuer_did;
        this.schema_name = schema_name;
        this.schema_version = schema_version;
        this.issuer_did = issuer_did;
        this.cred_def_id = cred_def_id;
    }
}
