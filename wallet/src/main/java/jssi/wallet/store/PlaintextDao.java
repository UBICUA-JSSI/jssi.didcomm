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

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.stmt.UpdateBuilder;
import jssi.wallet.model.Plaintext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;

/**
 *
 * @author ITON Solutions
 */
public class PlaintextDao implements Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(PlaintextDao.class);
    private Dao<Plaintext, Void> dao = null;

    public PlaintextDao(){
        try{
            dao = DaoManager.createDao(StoreHelper.getSource(), Plaintext.class);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
    }

    public int create(Plaintext plaintext)  {
        int result = 0;
        try {
            result = dao.create(plaintext);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }

    public int create(Collection<Plaintext> plaintext)  {
        int result = 0;
        try {
            result = dao.create(plaintext);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }

    public int update(Collection<Plaintext> plaintext)  {
        int result = 0;
        try {
            for(Plaintext element : plaintext) {
                UpdateBuilder<Plaintext, Void> builder = dao.updateBuilder();
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

    public int delete(Collection<Plaintext> plaintext)  {
        int result = 0;
        try {
            for(Plaintext element : plaintext) {
                DeleteBuilder<Plaintext, Void> builder = dao.deleteBuilder();
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

    public List<Plaintext> queryForAll() throws SQLException {
         return dao.queryForAll();
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
