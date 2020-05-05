package io.iohk.protocol.voting

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup

trait VoterBallot extends Ballot {

  def encryptedUnitVector: UnitVector
  def weightedUnitVector(implicit group: DiscreteLogGroup): UnitVector
}
