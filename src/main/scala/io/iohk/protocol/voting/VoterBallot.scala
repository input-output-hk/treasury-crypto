package io.iohk.protocol.voting

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup

trait VoterBallot extends Ballot {

  def encryptedUnitVector: EncryptedUnitVector
  def weightedUnitVector(implicit group: DiscreteLogGroup): EncryptedUnitVector
}
