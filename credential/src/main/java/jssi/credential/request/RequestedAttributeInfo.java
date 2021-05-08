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

package jssi.credential.request;

import jssi.credential.proof.AttributeInfo;

public class RequestedAttributeInfo {
    public String attr_referent;
    public AttributeInfo attr_info;
    public boolean revealed;

    public RequestedAttributeInfo(String attr_referent, AttributeInfo attr_info, boolean revealed){
        this.attr_referent = attr_referent;
        this.attr_info = attr_info;
        this.revealed = revealed;
    }
}
