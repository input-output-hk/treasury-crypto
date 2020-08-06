package io.iohk.protocol.voting.approval.multi_delegation

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup

trait MultiDelegVoterBallot extends MultiDelegBallot {

  def encryptedUnitVector: EncryptedUnitVector
  def weightedUnitVector(implicit group: DiscreteLogGroup): EncryptedUnitVector
}
