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

import org.miracl.core.BN254.*;

import java.util.Arrays;

import static org.miracl.core.BN254.BIG.NLEN;


/**
 *
 * @author ITON Solutions
 */
public class Pair {
    
    private static final int BYTES_REPR_SIZE = CONFIG_BIG.MODBYTES * 16;
    
    private FP12 pair;

    
    public static Pair pair(PointG1 p, PointG2 g) {
        FP12 pair = PAIR.fexp(PAIR.ate(g.point, p.point));
        pair.reduce();
        return new Pair(pair);
    }
    
    private Pair(FP12 pair){
        this.pair = pair;
    }

    public static Pair fromHex(String hex){
        return new Pair(FP12.fromHex(hex));
    }
    
    public Pair pow(GroupOrderElement g) {
        FP12 result = PAIR.GTpow(pair, g.big);
        return new Pair(result);
    }

    public byte[] toBytes() {
        
        byte[] result = new byte[BYTES_REPR_SIZE];
        pair.toBytes(result);
        return result;
    }

    public static Pair fromHex(String[] hex) throws CryptoException {
        if(hex.length != NLEN * 12){
            throw new CryptoException(String.format("Invalid array length: %d (must be %d", hex.length, NLEN * 12));
        }

        long[] longs = new long[NLEN];
        BIG[] bigs = new BIG[hex.length / NLEN];

        for(int i = 0; i < hex.length / NLEN; i++){
            longs[0] = Long.parseLong(hex[NLEN * i], 16);
            longs[1] = Long.parseLong(hex[NLEN * i + 1], 16);
            longs[2] = Long.parseLong(hex[NLEN * i + 2], 16);
            longs[3] = Long.parseLong(hex[NLEN * i + 3], 16);
            longs[4] = Long.parseLong(hex[NLEN * i + 4], 16);
            bigs[i] = new BIG(longs);
        }
        FP2[] fp2 = new FP2[bigs.length / 2];
        for(int i = 0; i < fp2.length; i++){
            fp2[i] = new FP2(bigs[2 * i], bigs[2 * i + 1]);
        }

        FP4[] fp4 = new FP4[fp2.length / 2];
        for(int i = 0; i < fp4.length; i++){
            fp4[i] = new FP4(fp2[2 * i], fp2[2 * i + 1]);
        }

        FP12 fp12 = new FP12(fp4[0], fp4[1], fp4[2]);
        return new Pair(fp12);
    }
    
    public Pair mul(Pair b) {
        FP12 result = new FP12(pair);
        result.mul(b.pair);
        result.reduce();
        return new Pair(result);
    }

    public Pair inverse() {
        FP12 result = new FP12(pair);
        result.conj();
        return new Pair(result);
    }

    public String toHex(){
        FP4 a = pair.geta();
        FP4 b = pair.getb();
        FP4 c = pair.getc();
        return String.format("%s %s %s", toHex(a), toHex(b), toHex(c));
    }

    private String toHex(FP2 fp){
        return String.format("%s %s", fp.getA().toHex(), fp.getB().toHex());
    }

    private String toHex(FP4 fp){
        return String.format("%s %s", toHex(fp.geta()), toHex(fp.getb()));
    }
    
    @Override
    public boolean equals(Object obj){
        if(obj instanceof Pair){
            Pair current = (Pair) obj;
            return Arrays.equals(this.toBytes(), current.toBytes());
        }
        return false;
    }

}
