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
The current cryptographic library implements different sub-protocols that constitute 
the core part of a treasury system - the voting protocol. These voting procol can be 
integrated in any blockchain system.

The full description of the protocol can be found in the paper [https://link](A Treasury System for Cryptocurrencies: Enabling Better Collaborative Intelligence)

The main features that are taken in consideration:
* Full verifiability - everyone should be able to verify the correctness of the voting
result
* Secrecy - personal choice of voter should not be disclosed
* Fairness - no one should have an advantage of knowing the partial results of the voting

The main actors of the voting procol are the following:
* Voters - an actor who makes a decision about particular proposal submitted to be voted
* Experts - an actor who makes a decision about particular proposal submitted to be 
voted and to whom regular voters may delegate their voting power
* Committee members - special actors who maintain the voting procedure (generate
distributed encryption key, do joint decryption of the result and etc.)

The library
-------------------
The library implemenst the following parts:
* Basic cryptographic primitives (Elgamal encryption, Hybrid encryption, Hash functions, etc.)
* Distributed Key Generation Protocol (proposed by Gennaro et al.[https://link.springer.com/chapter/10.1007/3-540-48910-X_21](Secure Distributed Key Generation for Discrete-Log Based Cryptosystems))
* Ballots encryption
* Joint decryption
* Randomness generation
* Non-ineractive zero-knowledge proofs

Current status
-------------------
Current implementation can't be considered as "production ready".

Other applications
-------------------
The implemented voting protocol can be used not only in the blockchain systems. 
It can be successfully reused, for instance, to deploy secure decentrilized fault 
tolerant voting schemes in some private networks where participating entities 
communicates directly with each other instead of using a blockchain as a channel.

Some cryptographic algorithms (like non-interective zero-knowkege proofs, Elgamal 
encryption, etc.) can be used separatily for other applications. 


