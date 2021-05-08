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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RevocationRegistryId {

    private static final Pattern PATTERN = Pattern.compile("(^revreg:(?<method>[a-z0-9]+):)?(?<did>.+):4:(?<creddef>.+):(?<type>.+):(?<tag>.+)$");

    public String id;

    public RevocationRegistryId(String id){
        this.id = id;
    }

    public void parse() {

        Matcher matcher = PATTERN.matcher(id);
        while(matcher.find()) {
            System.out.println(matcher.group("method"));
            System.out.println(matcher.group("did"));
            System.out.println(matcher.group("creddef"));
            System.out.println(matcher.group("type"));
            System.out.println(matcher.group("tag"));
        }
    }
}
