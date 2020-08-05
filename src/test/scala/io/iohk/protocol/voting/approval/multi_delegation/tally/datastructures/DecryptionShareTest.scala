package io.iohk.protocol.voting.approval.multi_delegation.tally.datastructures

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.{PrivKey, PubKey}
import io.iohk.core.crypto.encryption.elgamal.{ElGamalCiphertext, ElGamalEnc}
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.{ElgamalDecrNIZK, ElgamalDecrNIZKProof}
import org.scalatest.FunSuite

class DecryptionShareTest extends FunSuite {
  val ctx = new CryptoContext(None)
  import ctx.{group,hash}
  import DecryptionShareTest.createRandomDecryptionShare

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("check createRandomDecryptionShare") {
    val (ciphertexts, decryptionShare) = createRandomDecryptionShare(ctx, pubKey, privKey, 3, 5)
    require(decryptionShare.proposalId == 3)
    require(decryptionShare.decryptedC1.size == 5)
    require(ciphertexts.size == 5)

    require(decryptionShare.validate(ctx, pubKey, ciphertexts).isSuccess)
  }

  test("check DecryptionShare validation") {
    val (ciphertexts, decryptionShare) = createRandomDecryptionShare(ctx, pubKey, privKey, 3, 5)

    val wrongCiphertext = ciphertexts.reverse
    require(decryptionShare.validate(ctx, pubKey, wrongCiphertext).isFailure)

    val bogusCiphertext = ElGamalEnc.encrypt(pubKey, group.createRandomGroupElement.get).get._1
    val bogusProof = ElgamalDecrNIZK.produceNIZK(bogusCiphertext, privKey).get
    val decryptedC1 = decryptionShare.decryptedC1.toArray
    require(DecryptionShare(3, decryptedC1).validate(ctx, pubKey, ciphertexts).isSuccess)
    decryptedC1(0) = (decryptedC1(0)._1, bogusProof)
    require(DecryptionShare(3, decryptedC1).validate(ctx, pubKey, ciphertexts).isFailure)
  }

  test("DecryptionShare serialization") {
    val (ciphertexts, decryptionShare) = createRandomDecryptionShare(ctx, pubKey, privKey, 5, 2)
    val bytes = decryptionShare.bytes
    val restoredDecrShare = DecryptionShareSerializer.parseBytes(bytes, Option(group)).get

    require(decryptionShare.proposalId == 5)
    require(decryptionShare.validate(ctx, pubKey, ciphertexts).isSuccess)
  }
}

object DecryptionShareTest {

  def createRandomDecryptionShare(ctx: CryptoContext,
                                  pubKey: PubKey,
                                  privKey: PrivKey,
                                  id: Int,
                                  size: Int): (Seq[ElGamalCiphertext], DecryptionShare) = {
    import ctx.{group,hash}

    val ciphertexts = for (i <- 1 to size) yield {
      val plaintext = group.createRandomGroupElement.get
      val ciphertext = ElGamalEnc.encrypt(pubKey, plaintext).get._1
      ciphertext
    }

    val shares =
      ciphertexts.map { c =>
        val decryptedC1 = c.c1.pow(privKey).get
        val proof = ElgamalDecrNIZK.produceNIZK(c, privKey).get
        (decryptedC1, proof)
      }

    (ciphertexts, DecryptionShare(id, shares))
  }
}