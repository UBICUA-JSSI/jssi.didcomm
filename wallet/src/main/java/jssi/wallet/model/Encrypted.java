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
package jssi.wallet.model;

import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "tags_encrypted")
public class Encrypted extends Tag {

    public Encrypted() {
    }

    public Encrypted(Item item, byte[] name, byte[] value) {
        this.item = item;
        this.name = name;
        this.value = value;
    }

    @Override
    public String toString() {
        return "Encrypted[ id=" + item.getId() + " ]";
    }
    
}
