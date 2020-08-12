package io.iohk.protocol.voting.approval.uni_delegation

import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup

trait UniDelegVoterBallot extends UniDelegBallot {

  def weightedDelegationVector(implicit group: DiscreteLogGroup): Vector[ElGamalCiphertext]
  def weightedChoiceVectors(implicit group: DiscreteLogGroup): List[Vector[ElGamalCiphertext]]
}
