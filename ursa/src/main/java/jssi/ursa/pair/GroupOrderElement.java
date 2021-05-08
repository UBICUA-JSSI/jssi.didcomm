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
import org.miracl.core.BN254.CONFIG_BIG;
import org.miracl.core.BN254.ROM;
import org.miracl.core.RAND;
import jssi.ursa.util.Bytes;

import static org.miracl.core.BN254.BIG.NLEN;

/**
 *
 * @author ITON Solutions
 */
public class GroupOrderElement {
    
    public static final int BYTES_REPR_SIZE = CONFIG_BIG.MODBYTES;
    
    protected BIG big;
    
    public GroupOrderElement(){
        big = RandomGenerator.random();
    }
    
    public GroupOrderElement(BIG big){
        this.big = big;
    }
    
    public GroupOrderElement fromSeed(byte[] seed) throws CryptoException{
        // returns random element in 0, ..., GroupOrder-1
        if (seed.length != CONFIG_BIG.MODBYTES) {
            throw new CryptoException(String.format("Invalid len of seed: expected %d, actual %d", CONFIG_BIG.MODBYTES, seed.length));
        }
        RAND rand = new RAND();
        rand.clean();
        rand.seed(seed.length, seed);

        BIG result = BIG.randomnum(new BIG(ROM.CURVE_Order), rand);
        return new GroupOrderElement(result);
    }
    
    public byte[] toBytes() {
        byte[] result = new byte[BYTES_REPR_SIZE];
        big.toBytes(result);
        return result;
    }

    public String toHex() {
        return big.toHex();
    }

    public static GroupOrderElement fromHex(String hex) throws CryptoException {
        byte[] bytes = Bytes.toBytes(hex);
        return fromBytes(bytes);
    }

    public static GroupOrderElement fromHex(String[] hex) throws CryptoException {

        if(hex.length != NLEN){
            throw new CryptoException(String.format("Invalid array length: %d (must be %d", hex.length, NLEN));
        }

        BIG big = BIG.fromHex(hex);
        return new GroupOrderElement(big);
    }
    
    public static GroupOrderElement fromBytes(byte[] data) throws CryptoException {
        if (data.length > BYTES_REPR_SIZE) {
            throw new CryptoException("Invalid length of bytes representation");
        }
        
        int length = data.length;
        if (length < CONFIG_BIG.MODBYTES) {
            byte[] diff = new byte[CONFIG_BIG.MODBYTES - length];
            byte[] conc = Bytes.concat(diff, data);
            
            BIG result = BIG.fromBytes(conc);
            return new GroupOrderElement(result);
        }
        
        BIG result = BIG.fromBytes(data);
        return new GroupOrderElement(result);
    }
    
    public GroupOrderElement mulmod(GroupOrderElement g){
        BIG result = BIG.modmul(big, g.big, new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }

    /// 1 / GroupOrderElement
    public GroupOrderElement inverse() {
        BIG result = new BIG(big);
        result.invmodp(new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }

    /// - GroupOrderElement mod GroupOrder
    public GroupOrderElement modneg() {
        BIG result = new BIG(big);
        result = BIG.modneg(result, new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }

    public GroupOrderElement powmod(GroupOrderElement e) {
        BIG base = this.big;
        BIG pow = e.big;
        BIG result = base.powmod(pow, new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }

    /// (GroupOrderElement + GroupOrderElement) mod GroupOrder
    public GroupOrderElement addmod(GroupOrderElement r) {
        BIG result = new BIG(big);
        result.add(r.big);
        result.mod(new BIG(ROM.CURVE_Order));
        return new GroupOrderElement(result);
    }
}
