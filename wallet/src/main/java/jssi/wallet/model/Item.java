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
import com.j256.ormlite.field.ForeignCollectionField;
import com.j256.ormlite.misc.BaseDaoEnabled;
import com.j256.ormlite.table.DatabaseTable;

import java.util.Collection;

@DatabaseTable(tableName = "items")
public class Item extends BaseDaoEnabled {

    @DatabaseField(columnName = "id", generatedId = true)
    private Integer id;
    @DatabaseField(columnName = "type", uniqueCombo=true, dataType = DataType.BYTE_ARRAY)
    private byte[] type;
    @DatabaseField(columnName = "name", uniqueCombo=true, dataType = DataType.BYTE_ARRAY)
    private byte[] name;
    @DatabaseField(columnName = "value", dataType = DataType.BYTE_ARRAY)
    private byte[] value;
    @DatabaseField(columnName = "key", dataType = DataType.BYTE_ARRAY)
    private byte[] key;
    @ForeignCollectionField(foreignFieldName = "item", eager = false)
    Collection<Plaintext> plaintext;
    @ForeignCollectionField(foreignFieldName = "item", eager = false)
    Collection<Encrypted> encrypted;

    public Item() {
    }

    public Item(Integer id) {
        this.id = id;
    }

    public Item(byte[] type, byte[] name, byte[] value, byte[] key) {
        this.type = type;
        this.name = name;
        this.value = value;
        this.key = key;
    }

    public Integer getId() {
        return id;
    }

    public byte[] getType() {
        return type;
    }

    public void setType(byte[] type) {
        this.type = type;
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

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public Collection<Encrypted> getEncrypted() {
        return encrypted;
    }

    public void setEncrypted(Collection<Encrypted> encrypted) {
        this.encrypted = encrypted;
    }

    public Collection<Plaintext> getPlaintext() {
        return plaintext;
    }

    public void setPlaintext(Collection<Plaintext> plaintext) {
        this.plaintext = plaintext;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (id != null ? id.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Item)) {
            return false;
        }
        Item other = (Item) object;
        return (this.id != null || other.id == null) && (this.id == null || this.id.equals(other.id));
    }

    @Override
    public String toString() {
        return "Item[ id=" + id + " ]";
    }
}
