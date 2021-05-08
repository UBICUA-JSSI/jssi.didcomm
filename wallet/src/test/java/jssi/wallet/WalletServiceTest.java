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
package jssi.wallet;

import io.reactivex.Observable;
import io.reactivex.Observer;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Function;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;

import jssi.wallet.record.WalletRecord;
import jssi.wallet.store.PreexistingEntityException;
import jssi.wallet.store.StoreHelper;
import org.json.JSONObject;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class WalletServiceTest {
    
    private static final Logger LOG = LoggerFactory.getLogger(WalletService.class);
    
    public WalletServiceTest() {
        NaCl.sodium();
//        StoreHelper.setBackupSource();
        StoreHelper.setDefaultSource();
    }

    /**
     * Test of export method, of class WalletService.
     * @throws IOException
     * @throws SodiumException
     * @throws InterruptedException
     */
    @Test
    @Order(2)
    public void testExport() throws IOException, SodiumException, InterruptedException {
        StoreHelper.setDefaultSource();
        JSONObject credentials = new JSONObject();
        credentials.put("id", "ubicua");
        credentials.put("key", "wallet_key");
        WalletService service = new WalletService(credentials);
        
        JSONObject config = new JSONObject();
        config.put("path", WalletConstants.WALLET_DIR + "ubicua.backup");
        config.put("key", "wallet_key");
        
        service.export(config).subscribe(new Observer<Integer>(){
            @Override
            public void onSubscribe(Disposable disposable) {
                LOG.debug("Received SUBSCRIBED event");
            }

            @Override
            public void onNext(Integer count) {
                LOG.debug(String.format("Register %d processed", count));
            }

            @Override
            public void onError(Throwable throwable) {
                LOG.debug(String.format("Received error %s", throwable.getMessage()));
            }

            @Override
            public void onComplete() {
               LOG.debug("Received COMPLETED event");
            }
        });
        
        Thread.sleep(3000);
    }

    /**
     * Test of restore method, of class WalletService.
     * @throws IOException
     * @throws SodiumException
     * @throws InterruptedException
     */
    @Test
    @Order(4)
    public void testRestore() throws IOException, SodiumException, InterruptedException, Exception {
        JSONObject credentials = new JSONObject();
        credentials.put("id", "ubicua");
        credentials.put("key", "wallet_key");
        WalletService service = new WalletService(credentials);

        JSONObject config = new JSONObject();
        config.put("path", WalletConstants.WALLET_DIR + "ubicua.backup");
        config.put("key", "wallet_key");

        service.restore(config).subscribe(new Observer<Integer>() {
            @Override
            public void onSubscribe(Disposable disposable) {
                LOG.debug("Received SUBSCRIBED event");
            }

            @Override
            public void onNext(Integer count) {
                LOG.debug(String.format("Register %d restored", count));
            }

            @Override
            public void onError(Throwable throwable) {
                LOG.debug(String.format("Received error %s", throwable.getMessage()));
            }

            @Override
            public void onComplete() {
                LOG.debug("Received COMPLETED event");
            }
        });

        service.open().subscribe(new Observer<Wallet>() {
            @Override
            public void onSubscribe(Disposable disposable) {
                LOG.debug("Received SUBSCRIBED event");
            }

            @Override
            public void onNext(Wallet wallet) {
                try {
                    LOG.debug(String.format("Wallet opened: id=%s", wallet.getId()));
                    List<WalletRecord> records = wallet.findAllRecords();
                    for (WalletRecord record : records) {
                        LOG.debug(String.format("Record: name: %s type: %s value: %s", record.getName(), record.getType(), record.getValue()));
                        for(String key : record.getTags().keySet()){
                            LOG.debug(String.format("%s: name: %s value: %s", key.startsWith("~") ? "Plaintext" : "Encrypted", key, record.getTags().get(key)));
                        }
                    }
                    assertNotNull(records);
                } catch (SodiumException | SQLException e) {
                }
            }

            @Override
            public void onError(Throwable throwable) {
            }

            @Override
            public void onComplete() {
                LOG.debug("Received COMPLETED event");
            }
        });

        Thread.sleep(3000);
    }

    /**
     * Test of create method, of class WalletService.
     * @throws SodiumException
     * @throws IOException
     */
    @Test
    @Order(3)
    public void testCreate() throws SodiumException, IOException, PreexistingEntityException, InterruptedException {
        StoreHelper.createTables();
        JSONObject credentials = new JSONObject();
        credentials.put("id", "ubicua");
        credentials.put("key", "wallet_key");
        WalletService service = new WalletService(credentials);
        
        service.create().flatMap(new Function<Boolean, Observable<Wallet>>() {
            @Override
            public Observable<Wallet> apply(Boolean created) throws Exception {
                return service.open();
            }
        }).subscribe(new Observer<Wallet>() {
            @Override
            public void onSubscribe(Disposable dspsbl) {
                 LOG.debug("Received SUBSCRIBED event");
            }

            @Override
            public void onNext(Wallet wallet) {
                LOG.debug(String.format("Wallet created: id=%s", wallet.getId()));
                assertNotNull(wallet);
            }

            @Override
            public void onError(Throwable thrwbl) {
            }

            @Override
            public void onComplete() {
                LOG.debug("Received COMPLETED event");
            }
           
        });
        Thread.sleep(1000);
    }

    @Test
    @Order(5)
    public void testFindAll() throws InterruptedException {
        JSONObject credentials = new JSONObject();
        credentials.put("id", "ubicua_wallet");
        credentials.put("key", "ubicua_wallet_key");
        WalletService service = new WalletService(credentials);

        service.open().subscribe(new Observer<Wallet>() {
            @Override
            public void onSubscribe(Disposable disposable) {
                LOG.debug("Received SUBSCRIBED event");
            }

            @Override
            public void onNext(Wallet wallet) {
                try {
                    LOG.debug(String.format("Wallet opened: id=%s", wallet.getId()));
                    List<WalletRecord> records = wallet.findAllRecords();
                    for (WalletRecord record : records) {
                        LOG.debug(String.format("Record: name: %s type: %s value: %s", record.getName(), record.getType(), record.getValue()));
                        for(String key : record.getTags().keySet()){
                            LOG.debug(String.format("%s: name: %s value: %s", key.startsWith("~") ? "Plaintext" : "Encrypted", key, record.getTags().get(key)));
                        }
                    }
                    assertNotNull(records);
                } catch (SodiumException | SQLException e) {
                }
            }

            @Override
            public void onError(Throwable throwable) {
            }

            @Override
            public void onComplete() {
                LOG.debug("Received COMPLETED event");
            }
        });
        Thread.sleep(1000);
    }

    @Test
    @Order(1)
    public void testOpen() throws InterruptedException {
        JSONObject credentials = new JSONObject();
        credentials.put("id", "ubicua");
        credentials.put("key", "wallet_key");
        WalletService service = new WalletService(credentials);

        service.open().subscribe(new Observer<Wallet>() {
            @Override
            public void onSubscribe(Disposable disposable) {
                LOG.debug("Received SUBSCRIBED event");
            }

            @Override
            public void onNext(Wallet wallet) {
                LOG.debug(String.format("Wallet opened: id=%s", wallet.getId()));
                assertNotNull(wallet);
            }

            @Override
            public void onError(Throwable throwable) {
            }

            @Override
            public void onComplete() {
                LOG.debug("Received COMPLETED event");
            }
        });
        Thread.sleep(1000);
    }
    
}
