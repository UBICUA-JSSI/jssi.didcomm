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
import jssi.wallet.model.Metadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;


public class MetadataDao {

    private static final Logger LOG = LoggerFactory.getLogger(MetadataDao.class);
    private Dao<Metadata, Integer> dao = null;

    public MetadataDao(){
        try{
            dao = DaoManager.createDao(StoreHelper.getSource(), Metadata.class);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
    }

    public void create(Metadata metadata) {
        try {
            if(dao.countOf() > 0){
                LOG.error(String.format("Error: %s", "Metadata already exists"));
                return;
            }
            dao.create(metadata);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
    }

    public Metadata getMetadata() {
        Metadata result = null;
        try {
            result = dao.queryForId(1);
        } catch(SQLException e){
            LOG.error(String.format("Error: %s", e));
        }
        return result;
    }
}
