package io.iohk.protocol.voting.preferential.tally.datastructures

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.ElGamalEnc
import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.ElgamalDecrNIZK
import org.scalatest.FunSuite

class PrefTallyR1DataTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import PrefTallyR1DataTest.createRandomDecryptionShares
  import ctx.{group, hash}

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("check PrefTallyR1Data validation") {
    val (ciphertexts, decryptionShare) = createRandomDecryptionShares(ctx, pubKey, privKey, 5)

    val r1Data = PrefTallyR1Data(0, decryptionShare)
    require(r1Data.validate(ctx, pubKey, ciphertexts))

    val wrongCiphertext = ciphertexts.reverse
    require(r1Data.validate(ctx, pubKey, wrongCiphertext) == false)

    val bogusCiphertext = ElGamalEnc.encrypt(pubKey, group.createRandomGroupElement.get).get._1
    val bogusProof = ElgamalDecrNIZK.produceNIZK(bogusCiphertext, privKey).get
    val badR1Data = PrefTallyR1Data(0, (r1Data.delegDecryptedC1.head._1, bogusProof) +: r1Data.delegDecryptedC1.tail)
    require(badR1Data.validate(ctx, pubKey, ciphertexts) == false)

    val badR1Data2 = PrefTallyR1Data(0, (r1Data.delegDecryptedC1.tail.head._1, r1Data.delegDecryptedC1.tail.head._2) +: r1Data.delegDecryptedC1.tail)
    require(badR1Data2.validate(ctx, pubKey, ciphertexts) == false)

    val badR1Data3 = PrefTallyR1Data(0, r1Data.delegDecryptedC1.tail)
    require(badR1Data3.validate(ctx, pubKey, ciphertexts) == false)
  }

  test("PrefTallyR1Data serialization") {
    val (ciphertexts, decryptionShare) = createRandomDecryptionShares(ctx, pubKey, privKey, 5)
    val r1Data = PrefTallyR1Data(55, decryptionShare)
    val bytes = r1Data.bytes
    val restoredR1Data = PrefTallyR1DataSerializer.parseBytes(bytes, Option(group)).get

    require(restoredR1Data.issuerID == 55)
    require(restoredR1Data.delegDecryptedC1.size == r1Data.delegDecryptedC1.size)
    require(restoredR1Data.validate(ctx, pubKey, ciphertexts))
  }
}

object PrefTallyR1DataTest {

  def createRandomDecryptionShares(ctx: CryptoContext,
                                  pubKey: PubKey,
                                  privKey: PrivKey,
                                  size: Int) = {
    import ctx.{group, hash}

    val ciphertexts = for (i <- 1 to size) yield {
      val plaintext = group.createRandomGroupElement.get
      val ciphertext = ElGamalEnc.encrypt(pubKey, plaintext).get._1
      ciphertext
    }

    val decryptedC1WithProofs =
      ciphertexts.map { c =>
        val decryptedC1 = c.c1.pow(privKey).get
        val proof = ElgamalDecrNIZK.produceNIZK(c, privKey).get
        (decryptedC1, proof)
      }

    (ciphertexts, decryptedC1WithProofs)
  }
}