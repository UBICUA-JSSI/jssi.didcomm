# jssi.didcomm

The project is aimed at developing an open-source Java implementation of [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/).

## Motivation

Secure asynchronous messaging represents a core approach to the agent-to-agent communications in partially disconnected and potentially insecure networks. Within the frame of the Self-Sovereign Identity (SSI) model, the [DIDComm Messaging v2](https://identity.foundation/didcomm-messaging/spec/) specification provides a methodology and definitions for building communication solutions atop the two main SSI concepts of [Decentralized IDentifier (DID)](https://www.w3.org/TR/did-core/) and [Verifiable Credential (VC)](https://www.w3.org/TR/vc-data-model/). On the other hand, the [IETF Messaging Layer Security (MLS)](https://datatracker.ietf.org/wg/mls/documents/) specifications has been proposed to tackle different aspects of messaging arhitecture and protocols, including end-to-end security and multicast group scalability. 

Combining the above-mentioned specifications, we pretend to design and develop a simple but practical DIDComm Messaging solution that relies on the SSI infrastructure components, like [DID Resolver](https://github.com/decentralized-identity/universal-resolver) and [DID Registrar](https://github.com/decentralized-identity/universal-registrar), and takes advantages of the existing MLS-compliant applications, such as [Signal](https://signal.org/), [WhatsApp](https://www.whatsapp.com/), etc.
