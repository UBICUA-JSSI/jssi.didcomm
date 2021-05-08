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

package jssi.credential.credential;


public class CredentialDefinitionId {

    private static final String DELIMITER = ":";
    private static final String PREFIX = "creddef";
    private static final String MARKER = "3";

    public String id;

    public CredentialDefinitionId(String id){
        this.id = id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CredentialDefinitionId that = (CredentialDefinitionId) o;

        return id.equals(that.id);
    }

    public Parts parts() {
        String[] parts = id.split(DELIMITER);

        if (parts.length == 4) {
            // Th7MpTaRZVRYnPiabds81Y:3:CL:1
            return new Parts(parts[0], parts[2], parts[3], new String());
        }

        if (parts.length == 5) {
            return new Parts(parts[0], parts[2], parts[3], parts[4]);
        }

        if (parts.length == 7) {
            // NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0
            StringBuilder builder = new StringBuilder();
            builder.append(parts[3]).append(DELIMITER)
                    .append(parts[4]).append(DELIMITER)
                    .append(parts[5]).append(DELIMITER)
                    .append(parts[6]);
            String schema_id = builder.toString();
            return new Parts(parts[0], parts[2], schema_id, new String());
        }

        if (parts.length == 8) {
            // NcYxiDXkpYi6ov5FcYDi1e:3:CL:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag
            StringBuilder builder = new StringBuilder();
            builder.append(parts[3]).append(DELIMITER)
                    .append(parts[4]).append(DELIMITER)
                    .append(parts[5]).append(DELIMITER)
                    .append(parts[6]);
            String schema_id = builder.toString();
            return new Parts(parts[0], parts[2], schema_id, parts[7]);
        }

        if (parts.length == 9) {
            // creddef:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:3:CL:3:tag
            StringBuilder builder = new StringBuilder();
            builder.append(parts[2]).append(DELIMITER)
                    .append(parts[3]).append(DELIMITER)
                    .append(parts[4]);
            String did = builder.toString();
            return new Parts(did, parts[6], parts[7], parts[8]);
        }

        if (parts.length == 16) {
            // creddef:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:3:CL:schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0:tag
            StringBuilder builder = new StringBuilder();
            builder.append(parts[2]).append(DELIMITER)
                    .append(parts[3]).append(DELIMITER)
                    .append(parts[4]);
            String did = builder.toString();

            builder = new StringBuilder();
            builder.append(parts[7]).append(DELIMITER)
                    .append(parts[8]).append(DELIMITER)
                    .append(parts[9]).append(DELIMITER)
                    .append(parts[10]).append(DELIMITER)
                    .append(parts[11]).append(DELIMITER)
                    .append(parts[12]).append(DELIMITER)
                    .append(parts[13]).append(DELIMITER)
                    .append(parts[14]);
            String schema_id = builder.toString();
            return new Parts(did, parts[6], schema_id, parts[15]);
        }

        return null;
    }

    public String getIssuerDid() {
        return parts().did;
    }

    public class Parts{
        public String did;
        public String signature_type;
        public String schema_id;
        public String tag;

        public Parts(String did, String signature_type, String schema_id, String tag){
            this.did = did;
            this.signature_type = signature_type;
            this.schema_id = schema_id;
            this.tag = tag;
        }
    }
}
