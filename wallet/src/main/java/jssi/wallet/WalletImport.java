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
import io.reactivex.ObservableEmitter;
import io.reactivex.ObservableOnSubscribe;
import jssi.wallet.io.Reader;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 *
 * @author ITON Solutions
 */
class WalletImport {
    private static final Logger LOG = LoggerFactory.getLogger(WalletImport.class);
    
    private final Wallet wallet;
    
    WalletImport(final Wallet wallet){
        this.wallet = wallet;
    }

    private class Emitter implements ObservableOnSubscribe<Integer> {

        JSONObject config;
        ExecutorService executor = Executors.newSingleThreadExecutor();

        Emitter(JSONObject config) {
            this.config = config;
        }

        @Override
        public void subscribe(ObservableEmitter<Integer> emitter) {
            executor.execute(new Reader(wallet, config, emitter));
        }
    }

    Observable<Integer> restore(JSONObject config) {
        return Observable.create(new Emitter(config));
    }

}
    
    
