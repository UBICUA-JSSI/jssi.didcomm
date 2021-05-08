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
import jssi.mls.util.guava.Optional;

public class BobProtocolParameters {

  private final IdentityKeyPair     ourIdentityKey;
  private final ECKeyPair           ourSignedPreKey;
  private final Optional<ECKeyPair> ourOneTimePreKey;
  private final ECKeyPair           ourRatchetKey;

  private final IdentityKey         theirIdentityKey;
  private final ECPublicKey         theirBaseKey;

  BobProtocolParameters(IdentityKeyPair ourIdentityKey, ECKeyPair ourSignedPreKey,
                        ECKeyPair ourRatchetKey, Optional<ECKeyPair> ourOneTimePreKey,
                        IdentityKey theirIdentityKey, ECPublicKey theirBaseKey)
  {
    this.ourIdentityKey   = ourIdentityKey;
    this.ourSignedPreKey  = ourSignedPreKey;
    this.ourRatchetKey    = ourRatchetKey;
    this.ourOneTimePreKey = ourOneTimePreKey;
    this.theirIdentityKey = theirIdentityKey;
    this.theirBaseKey     = theirBaseKey;

    if (ourIdentityKey == null || ourSignedPreKey == null || ourRatchetKey == null ||
        ourOneTimePreKey == null || theirIdentityKey == null || theirBaseKey == null)
    {
      throw new IllegalArgumentException("Null value!");
    }
  }

  public IdentityKeyPair getOurIdentityKey() {
    return ourIdentityKey;
  }

  public ECKeyPair getOurSignedPreKey() {
    return ourSignedPreKey;
  }

  public Optional<ECKeyPair> getOurOneTimePreKey() {
    return ourOneTimePreKey;
  }

  public IdentityKey getTheirIdentityKey() {
    return theirIdentityKey;
  }

  public ECPublicKey getTheirBaseKey() {
    return theirBaseKey;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public ECKeyPair getOurRatchetKey() {
    return ourRatchetKey;
  }

  public static class Builder {
    private IdentityKeyPair     ourIdentityKey;
    private ECKeyPair           ourSignedPreKey;
    private Optional<ECKeyPair> ourOneTimePreKey;
    private ECKeyPair           ourRatchetKey;

    private IdentityKey         theirIdentityKey;
    private ECPublicKey         theirBaseKey;

    public Builder setOurIdentityKey(IdentityKeyPair ourIdentityKey) {
      this.ourIdentityKey = ourIdentityKey;
      return this;
    }

    public Builder setOurSignedPreKey(ECKeyPair ourSignedPreKey) {
      this.ourSignedPreKey = ourSignedPreKey;
      return this;
    }

    public Builder setOurOneTimePreKey(Optional<ECKeyPair> ourOneTimePreKey) {
      this.ourOneTimePreKey = ourOneTimePreKey;
      return this;
    }

    public Builder setTheirIdentityKey(IdentityKey theirIdentityKey) {
      this.theirIdentityKey = theirIdentityKey;
      return this;
    }

    public Builder setTheirBaseKey(ECPublicKey theirBaseKey) {
      this.theirBaseKey = theirBaseKey;
      return this;
    }

    public Builder setOurRatchetKey(ECKeyPair ourRatchetKey) {
      this.ourRatchetKey = ourRatchetKey;
      return this;
    }

    public BobProtocolParameters create() {
      return new BobProtocolParameters(ourIdentityKey, ourSignedPreKey, ourRatchetKey,
                                             ourOneTimePreKey, theirIdentityKey, theirBaseKey);
    }
  }
}
