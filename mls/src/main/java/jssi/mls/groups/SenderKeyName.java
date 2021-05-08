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
package jssi.mls.groups;

import jssi.mls.ProtocolAddress;

/**
 * A representation of a (groupId + senderId + deviceId) tuple.
 */
public class SenderKeyName {

    private final String groupId;
    private final ProtocolAddress sender;

    public SenderKeyName(String groupId, ProtocolAddress sender) {
        this.groupId = groupId;
        this.sender = sender;
    }

    public String getGroupId() {
        return groupId;
    }

    public ProtocolAddress getSender() {
        return sender;
    }

    public String serialize() {
        return groupId + "::" + sender.getDid() + "::" + String.valueOf(sender.getDeviceId());
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) return false;
        if (!(other instanceof SenderKeyName)) return false;

        SenderKeyName that = (SenderKeyName) other;

        return this.groupId.equals(that.groupId) && this.sender.equals(that.sender);
    }

    @Override
    public int hashCode() {
        return this.groupId.hashCode() ^ this.sender.hashCode();
    }

}
