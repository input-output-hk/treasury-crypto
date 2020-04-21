package io.iohk.protocol.tally.datastructures

import io.iohk.core.crypto.encryption.hybrid.HybridPlaintext
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.datastructures.round4.OpenedShare
import org.scalatest.FunSuite

class TallyR2DataTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  test("TallyR2Data serialization") {
    val mockHybridPlaintext = HybridPlaintext(ctx.group.groupGenerator, Array.fill[Byte](5)(31))
    val mockOpenedShare = OpenedShare(receiverID = 5, mockHybridPlaintext)
    val issuerId = 134
    val tallyR2Data = TallyR2Data(issuerId, Array((2, mockOpenedShare), (5, mockOpenedShare)))

    val bytes = tallyR2Data.bytes
    val recoveredData = TallyR2DataSerializer.parseBytes(bytes, Option(group)).get

    require(recoveredData.issuerID == issuerId)
    require(recoveredData.violatorsShares.length == tallyR2Data.violatorsShares.length)
    recoveredData.violatorsShares.zip(tallyR2Data.violatorsShares).foreach { case (s1,s2) =>
      require(s1._1 == s2._1)
      require(s1._2.bytes.sameElements(s2._2.bytes))
    }
  }
}
