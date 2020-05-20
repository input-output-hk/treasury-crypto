package io.iohk.protocol.keygen.datastractures.round1

import io.iohk.core.crypto.encryption.hybrid.HybridPlaintext
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.protocol.keygen.datastructures_new.round1.{OpenedShare, OpenedShareSerializer}
import org.scalatest.FunSuite
import org.scalatest.prop.TableDrivenPropertyChecks

class OpenedShareTest extends FunSuite with TableDrivenPropertyChecks {

  val dlogGroups =
    Table(
      "group",
      AvailableGroups.values.toSeq.map(g => DiscreteLogGroupFactory.constructDlogGroup(g).get):_*
    )

  test("serialization") {
    forAll(dlogGroups) { implicit group =>
      val receiverId = 223

      val plaintext = HybridPlaintext(group.createRandomGroupElement.get, group.createRandomNumber.toByteArray)
      val openedShare = OpenedShare(receiverId, plaintext)
      val recoveredShare = OpenedShareSerializer.parseBytes(openedShare.bytes, Some(group)).get

      require(recoveredShare.receiverID == receiverId)
      require(recoveredShare.S.bytes.sameElements(plaintext.bytes))
    }
  }
}