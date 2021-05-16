# JDCM (Java DIDComm Messaging)
The project is aimed at developing JDCM, an open-source Java implementation of [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/).

## Motivation
Secure asynchronous messaging represents a core approach to the agent-to-agent communications in partially disconnected and potentially insecure networks. Within the frame of the Self-Sovereign Identity (SSI) model, the [DIDComm Messaging v2](https://identity.foundation/didcomm-messaging/spec/) specification provides a methodology and definitions for building communication solutions atop the two main SSI concepts of [Decentralized IDentifier (DID)](https://www.w3.org/TR/did-core/) and [Verifiable Credential (VC)](https://www.w3.org/TR/vc-data-model/). On the other hand, the [IETF Messaging Layer Security (MLS)](https://datatracker.ietf.org/wg/mls/documents/) specifications has been proposed to tackle different aspects of messaging arhitecture and protocols, including end-to-end security and multicast group scalability. 

Combining the above-mentioned specifications, we pretend to design and develop a simple but practical Java DIDComm Messaging (JDCM) solution that relies on the SSI infrastructure components, like Universal [DID Resolver](https://github.com/decentralized-identity/universal-resolver) and [DID Registrar](https://github.com/decentralized-identity/universal-registrar), and takes advantages of the existing MLS-compliant applications, such as [Signal](https://signal.org/), [WhatsApp](https://www.whatsapp.com/), etc.

## Requirements
With reference to the key requirements of DIDComm Messaging, JDCM is designed to be message-based, asynchronous and secure. The JDCM architecture will include all necessary infrastructure components and functional services to provide an asynchronous and secure message exchange between DID Subjects in SSI-compliant ecosystems.

### Message Types and Formats
JDCM supports the message types defined by the [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/) specification:
- **Plaintext Message** is a serializable data structure that consists of headers (metadata) and body (content). Although the JWM (JSON Web Messages) format is accepted as default, other formats, like [Protobuf](https://github.com/protocolbuffers/protobuf) or [MessagePack](https://msgpack.org/), can be incorporated later on. 
- **Signed Message** in a wrapper that contains inside a plaintext message with a non-repudiable signature. 
- **Encrypted Message** is an envelope that contains inside either plaintext or signed message and serves for secure and privacy-preserving purposes.

### Asynchronous Transfer
According to the [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/) specification, there are three roles involved in asynchronous message exchange: 
- **Sender** as an agent that writes, optionally signs, encrypts and forwards messages to Recipients using the Mediator services.
- **Recipient** as an agent that receives, decrypts and reads the Sender messages using the Mediator services.
- **Mediator** as a routing agent (service provider) that provides services for temporally storing the Sender messages and delivering them to Recipients when the latter become available.

### Privacy and Security
A secure messaging system must implement two basic features:
- **Authentication** to provide Session Layer Security (SLS),
- **Encryption** to provide Messaging Layer Security (MLS).

#### Authentication
Authentication is required to provide security of a messaging solution at the session layer. Within the SSI model, [DID Authentication](https://github.com/WebOfTrustInfo/rwot6-santabarbara/blob/master/final-documents/did-auth.md) is proposed as a primary method of identity verification.

Each agent represents a DID Subject having the corresponding DID ad DID Document. Formally, a DID Subject possesses an individual state which is characterized by a set of identity attributes accompanied by public encryption keys and public signing keys. DID Authentication as a method by which a DID Subject proves a possession and control over the entire cryptographic state of an identity.

JDCM adopts DID Authentication as mandatory and reciprocal process which can be implemented in one of two modes:
- **Unilateral mode** in which DID Authentication is built atop the Transport Layer Security (TLS) together with public authority certificates (CA). 
- **Bilateral mode** in which both communicating DID Subjects rely on a common DID Authentication protocol.

As shown by [Diffie et al.](https://link.springer.com/article/10.1007/BF00124891), authentication-only solutions using long-term keys cannot protect communicating parties from some attacks, such as the Man-In-The-Middle (MITM) or Man-At-The-End (MATE) types. In insecure and unsafe environments, DID Authentication combined with a Key Exchange (KE), i.e. an exchange of a shared secret, seems preferable.

JDCM uses the reciprocal DID Authentication in all synchronous communications. In particular, a Sender or Recipient, on the one hand, and a Mediator, on the other hand, must mutually authenticate while establishing a secure communication channel.

#### Encryption
To be able to exchange encrypted messages in asynchronous and optionally multicasting way, two or more agents need to create a cryptographic group. The main goal of such a group is to ensure a Group Key Agreement (GKA) for deriving shared secret keys and updating them on the basis of a policy-based rotation.

Within the SSI model, we introduce a definition of DID Group as a set of DID Subjects that share a collective cryptographic state. A membership in a DID Group implies that each member has access to a group secret and can use it in communications with other members of the group.


