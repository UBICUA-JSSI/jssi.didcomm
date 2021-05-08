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

package jssi.credential.revocation;

import java.util.List;

public class RevocationRegistryInfo {

    public RevocationRegistryId id;
    public int curr_id;
    public List<Integer> used_ids;

    public RevocationRegistryInfo(RevocationRegistryId id, int curr_id, List<Integer> used_ids){
        this.id = id;
        this.curr_id = curr_id;
        this.used_ids = used_ids;
    }
}
