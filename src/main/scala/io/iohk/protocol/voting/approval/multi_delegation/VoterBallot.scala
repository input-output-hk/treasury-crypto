package io.iohk.protocol.voting.approval.multi_delegation

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.voting.approval.multi_delegation.approval.EncryptedUnitVector

trait VoterBallot extends Ballot {

  def encryptedUnitVector: EncryptedUnitVector
  def weightedUnitVector(implicit group: DiscreteLogGroup): EncryptedUnitVector
}
