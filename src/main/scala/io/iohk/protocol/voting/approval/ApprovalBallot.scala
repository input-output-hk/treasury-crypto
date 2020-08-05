package io.iohk.protocol.voting.approval

import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, LiftedElGamalEnc}
import io.iohk.core.crypto.encryption.{PubKey, Randomness}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.BytesSerializable


trait ApprovalBallot extends BytesSerializable {
  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte
  def verifyBallot(pctx: ApprovalContext, pubKey: PubKey): Boolean
}

object ApprovalBallot {
  object ApprovalBallotTypes extends Enumeration {
    val MultVoter, MultExpert, MultPrivateVoter,
        UniVoter, UniExpert, UniPrivateVoter = Value
  }

  def buildEncryptedUnitVector(size: Int, nonZeroPos: Int, key: PubKey)
                              (implicit group: DiscreteLogGroup)
  : (Vector[ElGamalCiphertext], Vector[Randomness]) = {
    val randomness = Vector.fill(size)(group.createRandomNumber)
    val ciphertexts = randomness.zipWithIndex.map { case (r, i) =>
      LiftedElGamalEnc.encrypt(key, r, if (i == nonZeroPos) 1 else 0).get
    }
    (ciphertexts, randomness)
  }
}