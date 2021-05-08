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
package jssi.wallet.io;

import io.reactivex.ObservableEmitter;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.List;

import jssi.wallet.Wallet;
import jssi.wallet.crypto.Crypto;
import jssi.wallet.crypto.KeyDerivationData;
import jssi.wallet.record.WalletRecord;
import jssi.wallet.util.Utils;
import org.json.JSONObject;
import org.libsodium.jni.SodiumException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Writer implements Runnable {

    private static final Logger LOG = LoggerFactory.getLogger(Writer.class);
    
    private Wallet wallet;
    private ObservableEmitter<Integer> emitter;
    private JSONObject config;

    public Writer(Wallet wallet, JSONObject config, ObservableEmitter<Integer> emitter) {
        this.wallet = wallet;
        this.config = config;
        this.emitter = emitter;
    }

    @Override
    public void run() {

        try {
            Path path = Paths.get(config.getString("path"));
            if (!Files.exists(path.getParent())) {
                Files.createDirectories(path.getParent());
            }

            int count = wallet.count();
            LOG.debug(String.format("Total registers in database %d", count));

            KeyDerivationData data = new KeyDerivationData(config.getString("key"));
            Header header = new Header();
            byte[] header_bytes = header.serialize(data);
            List<WalletRecord> records = wallet.findAllRecords();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(Crypto.hash256(header_bytes));

            for (WalletRecord record : records) {
                byte[] decrypted = record.serialize();
                baos.write(Utils.intToBytes(decrypted.length));
                baos.write(decrypted);
                emitter.onNext(count--);
            }

            baos.write(Utils.intToBytes(0));

            byte[] encrypted = new Encrypter(header.getDerivationData().deriveMasterKey(),
                    header.getNonce(),
                    header.getChunkSize()).encrypt(ByteBuffer.wrap(baos.toByteArray()));

            baos = new ByteArrayOutputStream();
            baos.write(Utils.intToBytes(header_bytes.length));
            baos.write(header_bytes);
            baos.write(encrypted);

            try (FileOutputStream fos = new FileOutputStream(Files.createFile(path).toFile())) {
                baos.writeTo(fos);
            }
            emitter.onComplete();

        } catch (IOException | SodiumException | SQLException e) {
            LOG.error(String.format("Error %s", e.getMessage()));
            emitter.onError(e);
        }
    }
}
