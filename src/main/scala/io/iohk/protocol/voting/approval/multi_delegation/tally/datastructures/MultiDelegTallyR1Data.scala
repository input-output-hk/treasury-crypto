package io.iohk.protocol.voting.approval.multi_delegation.tally.datastructures

import com.google.common.primitives.{Bytes, Ints, Shorts}
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.core.serialization.{BytesSerializable, Serializer}
import io.iohk.protocol.voting.common.Issuer

import scala.util.Try

case class MultiDelegTallyR1Data(issuerID: Int, // id of the committee member
                                 decryptionShares: Map[Int, DecryptionShare] // proposalId -> Decryption Share
                                ) extends BytesSerializable with Issuer {

  override type M = MultiDelegTallyR1Data
  override type DECODER = DiscreteLogGroup
  override val serializer: Serializer[M, DECODER] = MultiDelegTallyR1DataSerializer

  override val issuerId: Int = issuerID
}

object MultiDelegTallyR1DataSerializer extends Serializer[MultiDelegTallyR1Data, DiscreteLogGroup] {

  override def toBytes(obj: MultiDelegTallyR1Data): Array[Byte] = {

    val sharesBytes = obj.decryptionShares.foldLeft(Array[Byte]()) { (acc, s) =>
      val bytes = s._2.bytes
      Bytes.concat(acc, Ints.toByteArray(bytes.length), bytes)
    }
    Bytes.concat(
      Ints.toByteArray(obj.issuerID),
      Shorts.toByteArray(obj.decryptionShares.size.toShort), sharesBytes
    )
  }

  override def parseBytes(bytes: Array[Byte], decoder: Option[DiscreteLogGroup]): Try[MultiDelegTallyR1Data] = Try {

    val issuerId = Ints.fromByteArray(bytes.slice(0, 4))
    val sharesNum = Shorts.fromByteArray(bytes.slice(4, 6))
    var pos = 6
    val shares = (0 until sharesNum).map { _ =>
      val len = Ints.fromByteArray(bytes.slice(pos, pos + 4))
      val b = bytes.slice(pos + 4, pos + 4 + len)
      pos = pos + 4 + len
      DecryptionShareSerializer.parseBytes(b, decoder).get
    }

    val sharesMap = shares.map(s => (s.proposalId -> s)).toMap
    MultiDelegTallyR1Data(issuerId, sharesMap)
  }
}