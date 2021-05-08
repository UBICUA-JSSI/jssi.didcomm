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

import jssi.mls.ProtocolAddress;
import jssi.mls.state.SessionRecord;
import jssi.mls.state.SessionStore;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class InMemorySessionStore implements SessionStore {

    private Map<ProtocolAddress, byte[]> sessions = new HashMap<>();

    public InMemorySessionStore() {
    }

    @Override
    public synchronized SessionRecord loadSession(ProtocolAddress remoteAddress) {
        try {
            if (containsSession(remoteAddress)) {
                return new SessionRecord(sessions.get(remoteAddress));
            } else {
                return new SessionRecord();
            }
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public synchronized List<Integer> getSubDeviceSessions(String name) {
        List<Integer> deviceIds = new LinkedList<>();

        for (ProtocolAddress key : sessions.keySet()) {
            if (key.getDid().equals(name) &&
                    key.getDeviceId() != 1) {
                deviceIds.add(key.getDeviceId());
            }
        }

        return deviceIds;
    }

    @Override
    public synchronized void storeSession(ProtocolAddress address, SessionRecord record) {
        sessions.put(address, record.serialize());
    }

    @Override
    public synchronized boolean containsSession(ProtocolAddress address) {
        return sessions.containsKey(address);
    }

    @Override
    public synchronized void deleteSession(ProtocolAddress address) {
        sessions.remove(address);
    }

    @Override
    public synchronized void deleteAllSessions(String name) {
        for (ProtocolAddress key : sessions.keySet()) {
            if (key.getDid().equals(name)) {
                sessions.remove(key);
            }
        }
    }
}
