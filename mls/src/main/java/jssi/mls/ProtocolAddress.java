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
package jssi.mls;

public class ProtocolAddress {

    private final String did;
    private final int deviceId;

    public ProtocolAddress(String did, int deviceId) {
        this.did = did;
        this.deviceId = deviceId;
    }

    public String getDid() {
        return did;
    }

    public int getDeviceId() {
        return deviceId;
    }

    @Override
    public String toString() {
        return did + ":" + deviceId;
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) return false;
        if (!(other instanceof ProtocolAddress)) return false;

        ProtocolAddress that = (ProtocolAddress) other;
        return this.did.equals(that.did) && this.deviceId == that.deviceId;
    }

    @Override
    public int hashCode() {
        return this.did.hashCode() ^ this.deviceId;
    }
}
