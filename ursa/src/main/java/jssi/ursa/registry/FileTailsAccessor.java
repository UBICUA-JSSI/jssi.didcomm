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

package jssi.ursa.registry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jssi.ursa.pair.CryptoException;
import jssi.ursa.pair.PointG2;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileTailsAccessor implements RevocationTailsAccessor{

    private static final Logger LOG = LoggerFactory.getLogger(FileTailsAccessor.class);
    private Path path;

    private FileTailsAccessor(Path path){
        this.path = path;
    }

    public static FileTailsAccessor create(Path path, RevocationTailsGenerator generator){

        try {
            if (!Files.exists(path)) {
                Files.createDirectory(path);
                Tail tail = generator.next() ;
                int index = 1;
                while(tail != null){
                    Files.write(Paths.get(path.toString(), String.format("%05d", index++)), tail.toBytes());
                    tail = generator.next();
                }
            } else {
                LOG.debug(String.format("Directory [%s] already exist", path.toString()));
            }
        } catch(IOException e){
            LOG.error(String.format("File operation exception %s", e.getMessage()));
        }

        return new FileTailsAccessor(path);
    }

    @Override
    public Tail access(int index) {
        try {
            byte[] bytes = Files.readAllBytes(Paths.get(path.toString(), String.format("%05d", index)));
            return new Tail(PointG2.fromBytes(bytes));
        } catch(IOException | CryptoException e){
            LOG.error(String.format("File operation exception %s", e.getMessage()));
            return null;
        }
    }
}
