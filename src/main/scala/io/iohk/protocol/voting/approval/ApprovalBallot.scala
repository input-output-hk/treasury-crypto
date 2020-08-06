package io.iohk.protocol.voting.approval

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.BytesSerializable


//trait ApprovalBallot extends BytesSerializable {
//  override type DECODER = DiscreteLogGroup
//
//  def ballotTypeId: Byte
//  def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Boolean
//}