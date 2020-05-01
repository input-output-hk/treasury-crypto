package io.iohk.protocol.voting.ballots

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.crypto.primitives.hash.CryptographicHash
import io.iohk.protocol.nizk.shvzk.{SHVZKProof, SHVZKVerifier}
import io.iohk.protocol.nizk.unitvectornizk.MultRelationNIZK
import io.iohk.protocol.nizk.unitvectornizk.MultRelationNIZK.MultRelationNIZKProof
import io.iohk.protocol.voting.UnitVector
import io.iohk.protocol.voting.ballots.Ballot.BallotTypes

import scala.util.Try

case class PrivateVoterBallot(proposalId: Int,
                              uVector: UnitVector,
                              vVector: UnitVector,
                              uProof: Option[SHVZKProof],
                              vProof: Option[MultRelationNIZKProof],
                              encryptedStake: ElGamalCiphertext
                             ) extends Ballot {

  override type M = Ballot
  override val serializer = BallotSerializer

  override def ballotTypeId: Byte = BallotTypes.PrivateVoter.id.toByte

  def unitVector: Vector[ElGamalCiphertext] = uVector.combine
  def proof = uProof.get

  def verifyProofs(pubKey: PubKey)
                  (implicit group: DiscreteLogGroup, hash: CryptographicHash): Try[Unit] = Try {
    require(new SHVZKVerifier(pubKey, uVector.combine, uProof.get).verifyProof())
    require(MultRelationNIZK.verifyNIZK(pubKey, encryptedStake, uVector.combine, vVector.combine, vProof.get))
  }
}