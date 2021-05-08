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
package jssi.mls.protocol;

public interface CiphertextMessage {

    public static final int CURRENT_VERSION = 3;

    public static final int WHISPER_TYPE = 2;
    public static final int PREKEY_TYPE = 3;
    public static final int SENDERKEY_TYPE = 4;
    public static final int SENDERKEY_DISTRIBUTION_TYPE = 5;

    // This should be the worst case (worse than V2).  So not always accurate, but good enough for padding.
    public static final int ENCRYPTED_MESSAGE_OVERHEAD = 53;

    public byte[] serialize();

    public int getType();

}