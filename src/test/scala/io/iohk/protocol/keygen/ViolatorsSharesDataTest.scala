package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.hybrid.HybridPlaintext
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.datastructures.round4.OpenedShare
import io.iohk.protocol.keygen.datastructures.round5_1.{ViolatorsSharesData, ViolatorsSharesDataSerializer}
import org.scalatest.FunSuite

class ViolatorsSharesDataTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.group

  test("TallyR2Data serialization") {
    val mockHybridPlaintext = HybridPlaintext(ctx.group.groupGenerator, Array.fill[Byte](5)(31))
    val mockShare = Share(0, OpenedShare(receiverID = 5, mockHybridPlaintext), OpenedShare(receiverID = 5, mockHybridPlaintext))
    val issuerId = 134
    val tallyR2Data = new ViolatorsSharesData(issuerId, Seq(mockShare, mockShare))

    val bytes = tallyR2Data.bytes
    val recoveredData = ViolatorsSharesDataSerializer.parseBytes(bytes, Option(group)).get

    require(recoveredData.issuerID == issuerId)
    require(recoveredData.violatorsShares.length == tallyR2Data.violatorsShares.length)
    recoveredData.violatorsShares.zip(tallyR2Data.violatorsShares).foreach { case (s1,s2) =>
      require(s1.issuerID == s2.issuerID)
      require(s1.share_a.bytes.sameElements(s2.share_a.bytes))
      require(s1.share_b.bytes.sameElements(s2.share_b.bytes))
    }
  }
}
