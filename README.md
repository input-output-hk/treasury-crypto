Treasury crypto
====================================================================================================================================================================================
Treasury crypto is a cryptographic library for the developed decentrilized fault 
tolerant voting protocol for blockchain treasury system.

Motivation
-------------------
Modern cryptocurrencies are complex systems that require continuous maintenance.
Even though it is usually proclaimed that such systems are completely decentralized
and no one in full possession, all existing cryptocurrency systems have core team 
of members that, at least, controls the development effort.

It becomes crucial how this core team is funded, because in most cases a music is
played by those who pays money. If a core team is payed by some standalone investor
most likely they will follow his wishes that are not necesseraly beneficial for a 
cryptocurrency general well-being.

Treasury system aims to solve this problem by providing means for establishing 
collaborative consensus among all cryptocurency stakeholders about financing a system.
The source of funds is usually some part of block reward, but not restricted to be
only this one.

Voting protocol
-------------------
This cryptographic library implements a set of protocols that constitute 
the core part of a treasury system - the voting scheme. These voting procol can be 
integrated in any blockchain system.

The full description of the protocol can be found in the paper [A Treasury System for Cryptocurrencies: Enabling Better Collaborative Intelligence](https://eprint.iacr.org/2018/435.pdf)

The main features of the voting protocol:
* Full verifiability - everyone is able to verify the correctness of the voting
result
* Secrecy - personal choice of voter is not disclosed
* Fairness - no one has an advantage of knowing the partial results of the voting

The main actors of the voting procol are the following:
* Voters - an actor who makes a decision about particular proposal submitted to be voted
* Experts - an actor who makes a decision about particular proposal submitted to be 
voted and to whom regular voters may delegate their voting power
* Committee members - special actors who maintain the voting procedure (generate
distributed encryption key, do joint decryption of the result and etc.)

The library
-------------------
The library implemenst the following parts:
* Basic cryptographic protocols (Elgamal encryption, Hybrid encryption, wrappers for primitives, etc.)
* Distributed Key Generation Protocol (proposed by Gennaro et al.[Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](https://link.springer.com/chapter/10.1007/3-540-48910-X_21))
* Ballots encryption
* Joint decryption
* Randomness generation
* Non-ineractive zero-knowledge proofs

Current status
-------------------
Current implementation is a proof of concept. It is not for production usage.

Branch `new-crypto-primitives-layer` contains a fully rewritten layer of basic cryptographic protocols which now nicely abstracts interfaces for basic math, encryption schemes, hash functions, random number generators, etc. which allows flexible usage of different underlying crypto libraries (currently OpenSSL and BouncyCastle are supported). This part of the code is well-designed and may be of independent interest.

Other applications
-------------------
The implemented voting protocol can be used not only in the blockchain systems. 
It can be successfully reused, for instance, to deploy secure decentrilized fault 
tolerant voting schemes in some private networks where participating entities 
communicate directly with each other instead of using a blockchain as a channel.

Some cryptographic algorithms (like non-interective zero-knowkege proofs, Elgamal 
encryption, etc.) can be used separatily for other applications. 


