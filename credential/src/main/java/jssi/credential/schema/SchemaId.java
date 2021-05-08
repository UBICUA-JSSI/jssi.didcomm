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

package jssi.credential.schema;

public class SchemaId {
    private static final String DELIMITER = ":";

    public static final String PREFIX = "schema";
    public static final String MARKER = "2";

    public String id;

    public SchemaId(String id) {
        this.id = id;
    }

    public SchemaId(String did, String name, String version){
        id = String.format("%s%s%s%s%s%s%s", did, DELIMITER, MARKER, DELIMITER, name, DELIMITER, version);
    }

    public Parts  parts() {
        String[] parts = id.split(DELIMITER);

        if (parts.length == 1) {
            // 1
            return null;
        }

        if (parts.length == 4) {
            // NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0
            return new Parts(parts[0], parts[2], parts[3]);
        }

        if (parts.length == 8) {
            // schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0
            StringBuilder builder = new StringBuilder();
            builder.append(parts[2]).append(DELIMITER)
                    .append(parts[3]).append(DELIMITER)
                    .append(parts[4]).append(DELIMITER)
                    .append(parts[5]);
            String did = builder.toString();
            return new Parts(did, parts[6], parts[7]);
        }
        return null;
    }

    public class Parts{
        public String did;
        public String name;
        public String version;

        public Parts(String did, String name, String version){
            this.did = did;
            this.name = name;
            this.version = version;
        }
    }
}
