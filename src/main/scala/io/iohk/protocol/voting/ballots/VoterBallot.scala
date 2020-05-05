package io.iohk.protocol.voting.ballots

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.voting.UnitVector

trait VoterBallot extends Ballot {

  def encryptedUnitVector: UnitVector
  def weightedUnitVector(implicit group: DiscreteLogGroup): UnitVector
}
