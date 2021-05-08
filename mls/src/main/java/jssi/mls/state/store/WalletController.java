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

package jssi.mls.state.store;

import io.reactivex.Observable;
import io.reactivex.Observer;
import io.reactivex.disposables.Disposable;
import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.EDPrivateKey;
import jssi.mls.ecc.EDPublicKey;
import jssi.wallet.Wallet;
import jssi.wallet.WalletService;
import jssi.wallet.record.WalletRecord;
import org.bitcoinj.core.Base58;
import org.json.JSONObject;
import org.libsodium.jni.SodiumException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WalletController {

    private static final Logger LOG = LoggerFactory.getLogger(WalletController.class);
    private static final String DID_TYPE = "Indy::Did";
    private static final String KEY_TYPE = "Indy::Key";

    private ECKeyPair keyPair;
    private final String id;
    private final String key;
    private WalletListener listener;


    public WalletController(String id, String key){
        this.id = id;
        this.key = key;
    }

    public void setWalletListener(WalletListener listener){
        this.listener = listener;
    }

    public Observable<ECKeyPair> findKeyPair(String did){
        JSONObject credentials = new JSONObject();
        credentials.put("id", id);
        credentials.put("key", key);
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
                    WalletRecord didRecord = wallet.findRecord(DID_TYPE, did);
                    if(didRecord != null) {
                        LOG.debug(String.format("Found record: name: %s type %s value: %s", didRecord.getName(), didRecord.getType(), didRecord.getValue()));
                        JSONObject didResult = new JSONObject(didRecord.getValue());
                        WalletRecord keysRecord = wallet.findRecord(KEY_TYPE, didResult.getString("verkey"));
                        if(keysRecord != null) {
                            JSONObject keystResult = new JSONObject(keysRecord.getValue());
                            byte[] verkey = Base58.decode(keystResult.getString("verkey"));
                            byte[] signkey = Base58.decode(keystResult.getString("signkey"));
                            keyPair = new ECKeyPair(new EDPublicKey(verkey), new EDPrivateKey(signkey));
                        }
                    }
                } catch (SodiumException e){}
            }

            @Override
            public void onError(Throwable throwable) {
            }

            @Override
            public void onComplete() {
                LOG.debug("Received COMPLETED event");
                if(listener != null) {
                    listener.onWalletListener(keyPair);
                }
            }
        });
        return Observable.just(keyPair);
    }
}
