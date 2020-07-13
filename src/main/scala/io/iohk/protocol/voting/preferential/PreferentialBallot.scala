package io.iohk.protocol.voting.preferential

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.encryption.elgamal.ElGamalCiphertext
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.nizk.shvzk.{SHVZKProof, SHVZKVerifier}
import io.iohk.protocol.voting.preferential.PreferentialBallot.PreferentialBallotTypes

import scala.util.Try

abstract class PreferentialBallot (rankVectors: List[Vector[ElGamalCiphertext]],
                                   rankVectorsProofs: Option[List[SHVZKProof]]
                                  ) extends BytesSerializable {
  override type DECODER = DiscreteLogGroup

  def ballotTypeId: Byte

  def verifyBallot(pctx: PreferentialContext, pubKey: PubKey): Boolean = Try {
    import pctx.cryptoContext.{group, hash}
    require(rankVectors.size == pctx.numberOfRankedProposals)
    rankVectors.foreach(v => require(v.size == pctx.numberOfProposals))
    rankVectors.indices.foreach { i =>
      require(new SHVZKVerifier(pubKey, rankVectors(i), rankVectorsProofs.get(i)).verifyProof())
    }
  }.isSuccess
}

object PreferentialBallot {
  object PreferentialBallotTypes extends Enumeration {
    val Voter, Expert = Value
  }
}

object PreferentialBallotSerializer extends Serializer[PreferentialBallot, DiscreteLogGroup] {
  override def toBytes(b: PreferentialBallot): Array[Byte] =
    ???

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[PreferentialBallot] = Try {
    val ballotTypeId = bytes(0).toInt
    PreferentialBallotTypes(ballotTypeId) match {
      case PreferentialBallotTypes.Voter => ???
      case PreferentialBallotTypes.Expert => ???
    }
  }
}