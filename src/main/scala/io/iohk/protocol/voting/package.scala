package io.iohk.protocol

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext

package object voting {

  /**
    * A vote is represented as a unit vector of bits, where one bit is set to "1" while others are set to "0".
    * A unit vector of a regular voter comprises of two parts:
    *   1) delegation bits - if a voter wants to delegate, he sets to "1" one of the delegations bits. Each bit
    *   represents a particular expert;
    *   2) choice bits - if a voter wants to vote directly, he sets to "1" one of the choice bits depending on what he
    *   votes for
    *
    *  Example: let suppose we run a voting protocol with 5 experts and 2 options to chose from (e.g. Yes or No)
    *     - unit vector of a regular voter who wants to delegate to an expert #2 is "00100 00"
    *     - unit vector of a regular voter who votes directly for Yes is "00000 10"
    *     - unit vector of an expert who votes directly for No is "01". Note that experts cannot delegate so their
    *       vectors contain only choice bits.
    */

  /** A Vote class represents a vote */
  trait Vote {

    def isDirectVote: Boolean
    def isDelegatedVote: Boolean = !isDirectVote

    /** In case of a direct vote, it returns an integer representing the choice, otherwise returns None */
    def getDirectVote: Option[Int]

    /** In case of a delegated vote, it returns an integer representing the expert id, otherwise returns None */
    def getDelegatedVote: Option[Int]
  }

  case class DirectVote(choice: Int) extends Vote {
    override val isDirectVote = true
    override def getDirectVote = Some(choice)
    override def getDelegatedVote = None
  }

  case class DelegatedVote(expertId: Int) extends Vote {
    override val isDirectVote = false
    override def getDirectVote = None
    override def getDelegatedVote = Some(expertId)
  }

  /**
    * An encrypted unit vector which represents a voter choice. For convenience, a vector is split in two parts:
    *   1) a vector of encrypted delegation bits, and
    *   2) a vector of encrypted choice bits
    */
  case class EncryptedUnitVector(delegations: Vector[ElGamalCiphertext],
                                 choice: Vector[ElGamalCiphertext]) {
    def combine = delegations ++ choice
  }
}
