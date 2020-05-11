package io.iohk.protocol.keygen

import io.iohk.protocol.keygen.DistrKeyGenState.DKGStages
import io.iohk.protocol.keygen.datastructures_new.round1.R1Data
import io.iohk.protocol.{CryptoContext, Identifier}

import scala.util.Try

class DistrKeyGenState(ctx: CryptoContext, committee: Identifier[Int]) {
  import ctx.{blockCipher, group, hash}

  private var currentRound = DKGStages.Init
  def getCurrentRound = currentRound

  val committeeSize = committee.pubKeys.size
  val honestThreshold = (committeeSize.toFloat / 2).ceil.toInt   // Minimal number of honest members that must participate in the protocol

  protected val g = group.groupGenerator
  protected val h = ctx.commonReferenceString.get

  def verifyR1Data(r1Data: R1Data): Try[Unit] = Try {
    require(committee.getPubKey(r1Data.issuerID).isDefined, "Unrecognized issuer id!")
    require(r1Data.E.size == honestThreshold)
    require(r1Data.S_a.size == committeeSize - 1)
    require(r1Data.S_b.size == committeeSize - 1)

    val S_a_receivers = r1Data.S_a.map(_.receiverID).toSet
    val S_b_receivers = r1Data.S_b.map(_.receiverID).toSet
    require(S_a_receivers == S_b_receivers)
    S_a_receivers.foreach(r => committee.getPubKey(r).isDefined)
  }
}

object DistrKeyGenState {

  object DKGStages extends Enumeration {
    val Init, Round1, Round2, Round3, Round4, Round5 = Value
  }
}
