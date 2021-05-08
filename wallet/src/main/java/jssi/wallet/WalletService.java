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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.reactivex.Observable;
import io.reactivex.functions.Function;
import jssi.wallet.crypto.KeyDerivationData;
import jssi.wallet.crypto.Keys;
import jssi.wallet.crypto.KeysMetadata;
import jssi.wallet.model.Metadata;
import jssi.wallet.store.MetadataDao;
import org.json.JSONObject;
import org.libsodium.api.Crypto_randombytes;
import org.libsodium.jni.SodiumException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.Callable;

import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
/**
 *
 * @author ITON Solutions
 */
public class WalletService {
    
    private static final Logger LOG = LoggerFactory.getLogger(WalletService.class);
    
    private KeysMetadata keysMetadata;
    private KeyDerivationData keyDerivationData;
    private Keys keys;
    private final JSONObject credentials;
    private final MetadataDao metadataDao;
    private Wallet wallet;

    public WalletService(final JSONObject credentials) {
        this.credentials = credentials;
        this.metadataDao = new MetadataDao();
    }
    
    public Observable<Wallet> open(){
        if(wallet == null) {
            LOG.debug("Open wallet");
            return Observable.fromCallable(new Callable<Wallet>() {
                @Override
                public Wallet call() throws IOException, SodiumException {
                    Metadata metadata = new MetadataDao().getMetadata();
                    keysMetadata = new ObjectMapper()
                            .readerFor(KeysMetadata.class)
                            .readValue(metadata.getValue());
                    keyDerivationData = new KeyDerivationData(credentials.getString("key"), keysMetadata);
                    keys = new Keys().deserialize(keysMetadata.getKeys(), keyDerivationData.deriveMasterKey());
                    wallet = new Wallet(credentials.getString("id"), keys);
                    return wallet;
                }
            });
        } else {
            LOG.debug("Wallet already open");
            return Observable.just(wallet);
        }
    }

    public Observable<Boolean> close(){
        wallet = null;
        return Observable.just(Boolean.TRUE);
    }

    public Observable<Integer> export(JSONObject config) {
        return open().flatMap(new Function<Wallet, Observable<Integer>>() {
            @Override
            public Observable<Integer> apply(Wallet wallet) {
                WalletExport export = new WalletExport(wallet);
                return export.export(config);
            }
        });
    }
    
    public Observable<Integer> restore(JSONObject config) {
        
        return open().flatMap(new Function<Wallet, Observable<Integer>>() {
            @Override
            public Observable<Integer> apply(Wallet wallet) {
                WalletImport restore = new WalletImport(wallet);
                return restore.restore(config);
            }
        });
    }
    
    public Observable<Boolean> create() {
        return Observable.fromCallable(new Callable<Boolean>(){
            @Override
            public Boolean call() throws SodiumException, IOException {

                byte[] salt = new byte[CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES];
                Crypto_randombytes.buf(salt);
                keyDerivationData = new KeyDerivationData(credentials.getString("key"), salt);
                keys = new Keys().init();
                keysMetadata = new KeysMetadata(keys.serialize(keyDerivationData.deriveMasterKey()), salt);

                Metadata metadata = new Metadata(keysMetadata.toString().getBytes());
                metadataDao.create(metadata);
                return Boolean.TRUE;
            }
        });
    }

    public Wallet getWallet() {
        return wallet;
    }
}
