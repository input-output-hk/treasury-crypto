package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.shvzk.SHVZKVerifier
import io.iohk.protocol.voting.ballots.Ballot

abstract class Voter(val ctx: CryptoContext) {

  protected implicit val group = ctx.group
  protected implicit val hash = ctx.hash

  def publicKey: PubKey

  def verifyBallot(ballot: Ballot): Boolean = {
    new SHVZKVerifier(publicKey, ballot.unitVector, ballot.proof).verifyProof()
  }

  protected def produceUnitVector(size: Int, nonZeroPos: Int): (Array[ElGamalCiphertext], Array[Randomness]) = {
    val ciphertexts = new Array[ElGamalCiphertext](size)
    val randomness = new Array[Randomness](size)

    for (i <- 0 until size) {
      randomness(i) = group.createRandomNumber
      ciphertexts(i) = LiftedElGamalEnc.encrypt(publicKey, randomness(i), if (i == nonZeroPos) 1 else 0).get
    }

    (ciphertexts, randomness)
  }
}

object Voter {
  val VOTER_CHOISES_NUM = 3
}