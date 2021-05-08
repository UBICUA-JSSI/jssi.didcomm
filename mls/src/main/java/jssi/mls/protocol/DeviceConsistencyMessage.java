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

package jssi.mls.protocol;

//import org.whispersystems.curve25519.VrfSignatureVerificationFailedException;

import jssi.mls.IdentityKey;
import jssi.mls.IdentityKeyPair;
import jssi.mls.InvalidMessageException;
import jssi.mls.devices.DeviceConsistencyCommitment;

public class DeviceConsistencyMessage {

//  private final DeviceConsistencySignature  signature;
//  private final int                         generation;
//  private final byte[]                      serialized;

  public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, IdentityKeyPair identityKeyPair) {
//    try {
//      byte[] signatureBytes = Curve.calculateVrfSignature(identityKeyPair.getPrivateKey(), commitment.toByteArray());
//      byte[] vrfOutputBytes = Curve.verifyVrfSignature(identityKeyPair.getPublicKey().getPublicKey(), commitment.toByteArray(), signatureBytes);
//
//      this.generation = commitment.getGeneration();
//      this.signature  = new DeviceConsistencySignature(signatureBytes, vrfOutputBytes);
//      this.serialized = SignalProtos.DeviceConsistencyCodeMessage.newBuilder()
//                                                                  .setGeneration(commitment.getGeneration())
//                                                                  .setSignature(ByteString.copyFrom(signature.getSignature()))
//                                                                  .build()
//                                                                  .toByteArray();
//    } catch (InvalidKeyException | VrfSignatureVerificationFailedException e) {
//      throw new AssertionError(e);
//    }
  }

  public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, byte[] serialized, IdentityKey identityKey) throws InvalidMessageException {
//    try {
//      jssi.mls.protocol.SignalProtos.DeviceConsistencyCodeMessage message = SignalProtos.DeviceConsistencyCodeMessage.parseFrom(serialized);
//      byte[] vrfOutputBytes = Curve.verifyVrfSignature(identityKey.getPublicKey(), commitment.toByteArray(), message.getSignature().toByteArray());
//
//      this.generation = message.getGeneration();
//      this.signature  = new DeviceConsistencySignature(message.getSignature().toByteArray(), vrfOutputBytes);
//      this.serialized = serialized;
//    } catch (InvalidProtocolBufferException | InvalidKeyException | VrfSignatureVerificationFailedException e) {
//      throw new InvalidMessageException(e);
//    }
  }

//  public byte[] getSerialized() {
//    return serialized;
//  }
//
//  public DeviceConsistencySignature getSignature() {
//    return signature;
//  }
//
//  public int getGeneration() {
//    return generation;
//  }
}
