package io.iohk.protocol.tally.datastructures

import io.iohk.core.crypto.encryption
import io.iohk.protocol.CryptoContext
import org.scalatest.FunSuite
import DecryptionShareTest.createRandomDecryptionShare

class TallyR1DataTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.{group,hash}

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("TallyR1Data serialization") {
    val sharesWithVectors = (0 until 5).map { proposalId =>
      (proposalId -> createRandomDecryptionShare(ctx, pubKey, privKey, proposalId, 5))
    }

    val shares = sharesWithVectors.map(s => (s._1 -> s._2._2)).toMap
    val tallyR1Data = TallyR1Data(3, shares)

    val bytes = tallyR1Data.bytes
    val restoredData = TallyR1DataSerializer.parseBytes(bytes, Option(group)).get

    require(restoredData.issuerID == tallyR1Data.issuerID)
    require(restoredData.decryptionShares.size == tallyR1Data.decryptionShares.size)

    sharesWithVectors.foreach { case (proposalId, (ciphertexts, share)) =>
      require(restoredData.decryptionShares(proposalId).validate(ctx, pubKey, ciphertexts).isSuccess)
    }
  }
}
