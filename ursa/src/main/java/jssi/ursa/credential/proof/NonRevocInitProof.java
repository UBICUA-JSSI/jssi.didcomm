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

package jssi.ursa.credential.proof;

import java.util.List;

public class NonRevocInitProof {

    NonRevocProofXList c_list_params;
    NonRevocProofXList tau_list_params;
    NonRevocProofCList c_list;
    NonRevocProofTauList tau_list;

    public NonRevocInitProof(
            NonRevocProofXList c_list_params,
            NonRevocProofXList tau_list_params,
            NonRevocProofCList c_list,
            NonRevocProofTauList tau_list)
    {
        this.c_list_params = c_list_params;
        this.tau_list_params = tau_list_params;
        this.c_list = c_list;
        this.tau_list = tau_list;
    }

    public List<byte[]> toCList() {
        return c_list.toList();
    }

    public List<byte[]> toTauList() {
        return tau_list.toList();
    }
}
