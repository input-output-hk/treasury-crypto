package io.iohk.protocol.keygen

import io.iohk.protocol.keygen.DistrKeyGenState.DKGStages
import io.iohk.protocol.{CryptoContext, Identifier}

class DistrKeyGenState(ctx: CryptoContext, committeeIdentifier: Identifier[Int]) {
  import ctx.{blockCipher, group, hash}

  private var currentRound = DKGStages.Init
  def getCurrentRound = currentRound

  val committeeSize = committeeIdentifier.pubKeys.size
  val tolerableThreshold = (committeeSize.toFloat / 2).ceil.toInt   // Minimal number of honest members that must participate in the protocol

  protected val g = group.groupGenerator
  protected val h = ctx.commonReferenceString.get
}

object DistrKeyGenState {

  object DKGStages extends Enumeration {
    val Init, Round1, Round2, Round3, Round4, Round5 = Value
  }
}
