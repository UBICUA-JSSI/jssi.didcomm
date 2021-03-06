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
package jssi.mls.util;

import java.io.IOException;

/**
 * Utility for generating hex dumps.
 */
public class Hex {

  private final static char[] HEX_DIGITS = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };

  public static String toString(byte[] bytes) {
    return toString(bytes, 0, bytes.length);
  }

  public static String toString(byte[] bytes, int offset, int length) {
    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < length; i++) {
      appendHexChar(buf, bytes[offset + i]);
      buf.append(", ");
    }
    return buf.toString();
  }

  public static String toStringCondensed(byte[] bytes) {
    StringBuffer buf = new StringBuffer();
    for (int i=0;i<bytes.length;i++) {
      appendHexChar(buf, bytes[i]);
    }
    return buf.toString();
  }

  public static byte[] fromStringCondensed(String encoded) throws IOException {
    final char[] data = encoded.toCharArray();
    final int    len  = data.length;

    if ((len & 0x01) != 0) {
      throw new IOException("Odd number of characters.");
    }

    final byte[] out = new byte[len >> 1];

    for (int i = 0, j = 0; j < len; i++) {
      int f = Character.digit(data[j], 16) << 4;
      j++;
      f = f | Character.digit(data[j], 16);
      j++;
      out[i] = (byte) (f & 0xFF);
    }

    return out;
  }

  private static void appendHexChar(StringBuffer buf, int b) {
    buf.append("(byte)0x");
    buf.append(HEX_DIGITS[(b >> 4) & 0xf]);
    buf.append(HEX_DIGITS[b & 0xf]);
  }

}
