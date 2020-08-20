Treasury crypto
====================================================================================================================================================================================
Treasury crypto is a cryptographic library for the developed decentralized fault 
tolerant voting protocol. Initially, the voting protocol was designed for a blockchain treasury system, but it can also be used for other purposes.

Voting protocol
-------------------
The library implements the voting protocol, which is a core part of a treasury system. The voting protocol can be 
integrated in any blockchain system.

The full description of the protocol can be found in the paper [A Treasury System for Cryptocurrencies: Enabling Better Collaborative Intelligence](https://eprint.iacr.org/2018/435.pdf)

The main features of the voting protocol:
* Full verifiability - everyone is able to verify the correctness of the voting
result
* Secrecy - personal choice of a voter is not disclosed
* Fairness - no one has an advantage of knowing partial results of the voting

The main actors of the voting protocol are the following:
* Voter - an actor who makes a decision about a particular proposal submitted for ratification
* Expert - an actor who makes a decision about particular proposal submitted for ratification and to whom regular voters can delegate their voting power
* Committee members - special actors who maintain the voting procedure (generate
distributed encryption key, do joint decryption of the tally, etc.)

The library
-------------------
The library implements the following components:
* Basic cryptographic protocols (ElGamal encryption, hybrid encryption, wrappers for crypto primitives)
* A set of non-interactive zero-knowledge proofs
* Distributed Key Generation Protocol (based on the Gennaro's et.al. proposal [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](https://link.springer.com/chapter/10.1007/3-540-48910-X_21))
* Ballots encryption
* Joint decryption
* Randomness generation
* Several types of voting systems (approval voting, preferential voting)

Current status
-------------------
Current implementation is a prototype. Even though an effort was made to design it carefully with the aim to use in production, at this point it cannot be considered to be ready for that.

The old version of the library ([v0.1](https://github.com/input-output-hk/treasury-crypto/releases/tag/v0.1_treasury_coin)) was integrated into the full-fledged treasury prototype built on top of the Scorex framework ([TreasuryCoin](https://github.com/input-output-hk/TreasuryCoin))

Other applications
-------------------
The implemented voting protocol can be used not only for blockchain systems. 
It can be successfully reused, for instance, to deploy a secure decentralized fault 
tolerant voting scheme in some private network where participating entities 
communicate directly with each other instead of using a blockchain as a channel.

Some of the implemented cryptographic algorithms (e.g., non-interactive zero-knowledge proofs, ElGamal 
encryption, etc.) may be of particular interest for other applications. 


