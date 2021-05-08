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


import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import jssi.wallet.WalletConstants;
import jssi.wallet.model.Encrypted;
import jssi.wallet.model.Item;
import jssi.wallet.model.Metadata;
import jssi.wallet.model.Plaintext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;

public class StoreHelper {

    private static final Logger LOG = LoggerFactory.getLogger(StoreHelper.class);

//    private static final String DEFAULT_DB = "jdbc:sqlite:" + WalletConstants.WALLET_DIR + "ubicua.db";
    private static final String DEFAULT_DB = "jdbc:sqlite:" + WalletConstants.WALLET_DIR + "sqlite.db";
    private static final String BACKUP_DB  = "jdbc:sqlite:" + WalletConstants.WALLET_DIR + "backup.db";
    public static final StoreHelper INSTANCE =  new StoreHelper();
    private ConnectionSource source = null;


    private StoreHelper(){
        try {
            LOG.debug(String.format("Connect to database: %s", DEFAULT_DB));
            source = new JdbcConnectionSource(DEFAULT_DB);
        } catch(SQLException e) {
            LOG.error(String.format("Error: %s", e.getMessage()));
        }
    }

    public static ConnectionSource getSource() {
        return INSTANCE.source;
    }

    public static void setBackupSource(){
        try {
            LOG.debug(String.format("Connect to database: %s", BACKUP_DB));
            INSTANCE.source = new JdbcConnectionSource(BACKUP_DB);
        } catch(SQLException e) {
            LOG.error(String.format("Error: %s", e.getMessage()));
        }
    }

    public static void setDefaultSource(){
        try {
            LOG.debug(String.format("Connect to database: %s", DEFAULT_DB));
            INSTANCE.source = new JdbcConnectionSource(DEFAULT_DB);
        } catch(SQLException e) {
            LOG.error(String.format("Error: %s", e.getMessage()));
        }
    }

    public static void createTables(){
        try {
            LOG.debug(String.format("Create table: %s", "metadata"));
            TableUtils.createTableIfNotExists(INSTANCE.source, Metadata.class);
            TableUtils.createTableIfNotExists(INSTANCE.source, Item.class);
            TableUtils.createTableIfNotExists(INSTANCE.source, Encrypted.class);
            TableUtils.createTableIfNotExists(INSTANCE.source, Plaintext.class);
        } catch(SQLException e) {
            LOG.error(String.format("Error: %s", e.getMessage()));
        }

    }
}
