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

import com.j256.ormlite.field.DataType;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.misc.BaseDaoEnabled;

import java.util.Arrays;

public class Tag extends BaseDaoEnabled {


    @DatabaseField(columnName = "name", uniqueCombo=true, dataType = DataType.BYTE_ARRAY)
    byte[] name;
    @DatabaseField(columnName = "value", uniqueCombo=true, dataType = DataType.BYTE_ARRAY)
    byte[] value;
    @DatabaseField(columnName = "item_id",
            foreign = true,
            foreignAutoRefresh = true,
            foreignAutoCreate = true,
            canBeNull = false,
            index = true,
            columnDefinition = "INTEGER CONSTRAINT item_id REFERENCES items(id) ON DELETE CASCADE")
    Item item;

    public Tag() {
    }

    public Tag(Item item, byte[] name, byte[] value) {
        this.item = item;
        this.name = name;
        this.value = value;
    }

    public byte[] getName() {
        return name;
    }

    public void setName(byte[] name) {
        this.name = name;
    }

    public byte[] getValue() {
        return value;
    }

    public void setValue(byte[] value) {
        this.value = value;
    }

    public Item getItem() {
        return item;
    }

    public void setItem(Item item) {
        this.item = item;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (item != null ? item.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Tag)) {
            return false;
        }
        Tag other = (Tag) object;
        if ((this.item == null && other.item != null)
                || (this.item != null && !this.item.equals(other.item))
                || !Arrays.equals(this.name, other.name)
                || !Arrays.equals(this.value, other.value)) {
            return false;
        }
        return true;
    }
}
