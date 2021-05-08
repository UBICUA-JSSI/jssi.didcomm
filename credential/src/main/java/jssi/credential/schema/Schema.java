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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Schema {
    private SchemaId id;
    private String name;
    private String version;
    private AttributeNames attrNames;
    private int seqNo;

    @JsonCreator
    public Schema(
            @JsonProperty("id") SchemaId id,
            @JsonProperty("name") String name,
            @JsonProperty("version") String version,
            @JsonProperty("attrNames") AttributeNames attrNames,
            @JsonProperty("seqNo") int seqNo)
    {

        this.id = id;
        this.name = name;
        this.version = version;
        this.attrNames = attrNames;
        this.seqNo = seqNo;
    }

    public String getId() {
        return id.id;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public AttributeNames getAttrNames() {
        return attrNames;
    }

    public int getSeqNo() {
        return seqNo;
    }
}
