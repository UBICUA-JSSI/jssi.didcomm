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

package jssi.credential;

import jssi.credential.request.RequestedAttributeInfo;
import jssi.credential.request.RequestedPredicateInfo;

import java.util.ArrayList;
import java.util.List;

public class PreparedCredentialsValues {
    public List<RequestedAttributeInfo> requestedAttributeInfo = new ArrayList<>();
    public List<RequestedPredicateInfo> requestedPredicateInfo = new ArrayList<>();

    public PreparedCredentialsValues(){}

    public PreparedCredentialsValues(List<RequestedAttributeInfo> requestedAttributeInfo,
                                     List<RequestedPredicateInfo> requestedPredicateInfo) {
        this.requestedAttributeInfo = requestedAttributeInfo;
        this.requestedPredicateInfo = requestedPredicateInfo;

    }

}
