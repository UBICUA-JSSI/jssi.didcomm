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
package jssi.mls.fingerprint;

public class FingerprintVersionMismatchException extends Exception {

  private final int theirVersion;
  private final int ourVersion;

  public FingerprintVersionMismatchException(int theirVersion, int ourVersion) {
    super();
    this.theirVersion = theirVersion;
    this.ourVersion   = ourVersion;
  }

  public int getTheirVersion() {
    return theirVersion;
  }

  public int getOurVersion() {
    return ourVersion;
  }
}
