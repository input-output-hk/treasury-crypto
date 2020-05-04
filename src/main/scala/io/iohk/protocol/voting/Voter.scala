package io.iohk.protocol.voting

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.ProtocolContext
import io.iohk.protocol.voting.ballots.Ballot

abstract class Voter(val pctx: ProtocolContext) {

  protected implicit val group = pctx.cryptoContext.group
  protected implicit val hash = pctx.cryptoContext.hash

  def publicKey: PubKey

  def verifyBallot(ballot: Ballot): Boolean = {
    ballot.verifyBallot(pctx, publicKey).isSuccess
  }
}

object Voter {
  val VOTER_CHOISES_NUM = 3
}