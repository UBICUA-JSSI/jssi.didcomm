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
package jssi.wallet.store;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.stmt.UpdateBuilder;
import jssi.wallet.model.Encrypted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptedDao implements Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(EncryptedDao.class);
    private Dao<Encrypted, Void> dao = null;

    public EncryptedDao(){
        try{
            dao = DaoManager.createDao(StoreHelper.getSource(), Encrypted.class);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
    }

    public int create(Encrypted encrypted)  {
        int result = 0;
        try {
            result = dao.create(encrypted);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }

    public int create(Collection<Encrypted> encrypted)  {
        int result = 0;
        try {
            result = dao.create(encrypted);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }

    public int delete(Collection<Encrypted> encrypted)  {
        int result = 0;
        try {
            for(Encrypted element : encrypted) {
                DeleteBuilder<Encrypted, Void> builder = dao.deleteBuilder();
                builder.where()
                        .eq("item_id", element.getItem().getId())
                        .and()
                        .eq("name", element.getName());
                result = dao.delete(builder.prepare());
            }
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }

    public int update(Collection<Encrypted> encrypted)  {
        int result = 0;
        try {
            for(Encrypted element : encrypted) {
                UpdateBuilder<Encrypted, Void> builder = dao.updateBuilder();
                builder.updateColumnValue("value", element.getValue());
                builder.where()
                        .eq("item_id", element.getItem().getId())
                        .and()
                        .eq("name", element.getName());
                result += dao.update(builder.prepare());
            }
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
        return result;
    }

    public List<Encrypted> queryForAll() {
        List<Encrypted> result = new ArrayList<>();
        try {
            result = dao.queryForAll();
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
        return result;
    }

     public int getCount() {
        int result = 0;
        try {
            result = (int) dao.countOf();
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
        return result;
    }
}
