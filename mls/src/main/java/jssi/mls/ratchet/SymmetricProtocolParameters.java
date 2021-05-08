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
package jssi.mls.ratchet;

import jssi.mls.ecc.ECKeyPair;
import jssi.mls.ecc.ECPublicKey;
import jssi.mls.IdentityKey;
import jssi.mls.IdentityKeyPair;

public class SymmetricProtocolParameters {

  private final ECKeyPair       ourBaseKey;
  private final ECKeyPair       ourRatchetKey;
  private final IdentityKeyPair ourIdentityKey;

  private final ECPublicKey     theirBaseKey;
  private final ECPublicKey     theirRatchetKey;
  private final IdentityKey     theirIdentityKey;

  SymmetricProtocolParameters(ECKeyPair ourBaseKey, ECKeyPair ourRatchetKey,
                              IdentityKeyPair ourIdentityKey, ECPublicKey theirBaseKey,
                              ECPublicKey theirRatchetKey, IdentityKey theirIdentityKey)
  {
    this.ourBaseKey       = ourBaseKey;
    this.ourRatchetKey    = ourRatchetKey;
    this.ourIdentityKey   = ourIdentityKey;
    this.theirBaseKey     = theirBaseKey;
    this.theirRatchetKey  = theirRatchetKey;
    this.theirIdentityKey = theirIdentityKey;

    if (ourBaseKey == null || ourRatchetKey == null || ourIdentityKey == null ||
        theirBaseKey == null || theirRatchetKey == null || theirIdentityKey == null)
    {
      throw new IllegalArgumentException("Null values!");
    }
  }

  public ECKeyPair getOurBaseKey() {
    return ourBaseKey;
  }

  public ECKeyPair getOurRatchetKey() {
    return ourRatchetKey;
  }

  public IdentityKeyPair getOurIdentityKey() {
    return ourIdentityKey;
  }

  public ECPublicKey getTheirBaseKey() {
    return theirBaseKey;
  }

  public ECPublicKey getTheirRatchetKey() {
    return theirRatchetKey;
  }

  public IdentityKey getTheirIdentityKey() {
    return theirIdentityKey;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static class Builder {
    private ECKeyPair       ourBaseKey;
    private ECKeyPair       ourRatchetKey;
    private IdentityKeyPair ourIdentityKey;

    private ECPublicKey     theirBaseKey;
    private ECPublicKey     theirRatchetKey;
    private IdentityKey     theirIdentityKey;

    public Builder setOurBaseKey(ECKeyPair ourBaseKey) {
      this.ourBaseKey = ourBaseKey;
      return this;
    }

    public Builder setOurRatchetKey(ECKeyPair ourRatchetKey) {
      this.ourRatchetKey = ourRatchetKey;
      return this;
    }

    public Builder setOurIdentityKey(IdentityKeyPair ourIdentityKey) {
      this.ourIdentityKey = ourIdentityKey;
      return this;
    }

    public Builder setTheirBaseKey(ECPublicKey theirBaseKey) {
      this.theirBaseKey = theirBaseKey;
      return this;
    }

    public Builder setTheirRatchetKey(ECPublicKey theirRatchetKey) {
      this.theirRatchetKey = theirRatchetKey;
      return this;
    }

    public Builder setTheirIdentityKey(IdentityKey theirIdentityKey) {
      this.theirIdentityKey = theirIdentityKey;
      return this;
    }

    public SymmetricProtocolParameters create() {
      return new SymmetricProtocolParameters(ourBaseKey, ourRatchetKey, ourIdentityKey,
                                                   theirBaseKey, theirRatchetKey, theirIdentityKey);
    }
  }
}
