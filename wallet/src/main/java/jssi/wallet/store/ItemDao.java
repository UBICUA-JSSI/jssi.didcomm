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
import com.j256.ormlite.stmt.QueryBuilder;
import jssi.wallet.model.Item;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author ITON Solutions
 */
public class ItemDao implements Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(ItemDao.class);
    private Dao<Item, Integer> dao = null;

    public ItemDao(){
        try{
            dao = DaoManager.createDao(StoreHelper.getSource(), Item.class);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
    }

    public int create(Item item) {
        int result = 0;
        try {
            result = dao.create(item);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }

    public int update(Item item) {
        int result = 0;
        try {
            result = dao.update(item);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }

    public int delete(Item item) {
        int result = 0;
        try {
            result = dao.delete(item);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }

    public List<Item> queryForAll() {
        List<Item> items = new ArrayList<>();
        try {
            items = dao.queryForAll();
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return items;
    }

    public Item queryForFirst(byte[] type, byte[] name) {
        Item item = null;
        try {
            QueryBuilder<Item, Integer> builder = dao.queryBuilder();
            builder.where()
                    .eq("type", type)
                    .and()
                    .eq("name", name);

            item = dao.queryForFirst(builder.prepare());
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return item;
    }

    public int getCount() {
        int result = 0;
        try {
            result = (int) dao.countOf();
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e.getCause().getMessage()));
        }
        return result;
    }
    
}
