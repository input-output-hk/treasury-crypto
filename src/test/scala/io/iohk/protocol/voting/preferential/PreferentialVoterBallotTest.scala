package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite

class PreferentialVoterBallotTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("creation of VoterBallot with direct vote") {
    val pctx = new PreferentialContext(ctx, 10, 5, 3)

    val vote = DirectPreferentialVote(List(1,5,9,0,2))
    val ballot = PreferentialVoterBallot.createPreferentialVoterBallot(pctx, vote, pubKey, 2).get

    require(ballot.verifyBallot(pctx, pubKey))

    ballot.rankVectors.zip(vote.ranking).foreach { case (vector,nonZeroPos) =>
      for(i <- 0 until pctx.numberOfProposals) {
        val bit = LiftedElGamalEnc.decrypt(privKey, vector(i)).get
        if (i == nonZeroPos) require(bit == 1)
        else require(bit == 0)
      }
    }

    ballot.delegVector.tail.foreach{ b =>
      val bit = LiftedElGamalEnc.decrypt(privKey, b).get
      require(bit == 0)
    }

    require(1 == LiftedElGamalEnc.decrypt(privKey, ballot.w).get)
  }
}
