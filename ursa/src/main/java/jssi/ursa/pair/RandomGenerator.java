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
package jssi.ursa.pair;

import org.miracl.core.BN254.BIG;
import org.miracl.core.BN254.ROM;
import org.miracl.core.RAND;

import java.security.SecureRandom;

/**
 * @author ITON Solutions
 */
public class RandomGenerator {

    private static final int ENTROPY_BYTES = 128;

    public static BIG random() {

        byte[] seed = new byte[ENTROPY_BYTES];
        new SecureRandom().nextBytes(seed);
        RAND rand = new RAND();
        rand.seed(ENTROPY_BYTES, seed);

        return BIG.randomnum(new BIG(ROM.CURVE_Order), rand);
    }
}
