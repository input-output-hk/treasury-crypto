package io.iohk.protocol.voting.preferential.tally.datastructures

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.ElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.nizk.ElgamalDecrNIZK
import org.scalatest.FunSuite

class PrefTallyR3DataTestextends extends FunSuite {
  val ctx = new CryptoContext(None)
  import PrefTallyR1DataTest.createRandomDecryptionShares
  import ctx.{group, hash}

  val (privKey, pubKey) = encryption.createKeyPair.get

  test("check PrefTallyR3Data validation") {
    val vectors = (0 until 10).toList.map(_ => createRandomDecryptionShares(ctx, pubKey, privKey, 5))
    val shares = vectors.map(_._2)
    val ciphertexts = vectors.map(_._1)

    val r3Data = PrefTallyR3Data(0, shares)
    require(r3Data.validate(ctx, pubKey, ciphertexts))

    val wrongCiphertext = ciphertexts.reverse
    require(r3Data.validate(ctx, pubKey, wrongCiphertext) == false)

    val bogusCiphertext = ElGamalEnc.encrypt(pubKey, group.createRandomGroupElement.get).get._1
    val bogusProof = ElgamalDecrNIZK.produceNIZK(bogusCiphertext, privKey).get
    val bogusVector = (r3Data.rankingsDecryptedC1.head.head._1, bogusProof) +: r3Data.rankingsDecryptedC1.head.tail
    val badR3Data = PrefTallyR3Data(0, bogusVector :: r3Data.rankingsDecryptedC1.tail)
    require(badR3Data.validate(ctx, pubKey, ciphertexts) == false)

    val badVector = (r3Data.rankingsDecryptedC1.tail.head.head._1, r3Data.rankingsDecryptedC1.tail.head.head._2) +: r3Data.rankingsDecryptedC1.head.tail
    val badR1Data2 = PrefTallyR3Data(0, badVector :: r3Data.rankingsDecryptedC1.tail)
    require(badR1Data2.validate(ctx, pubKey, ciphertexts) == false)

    val badR1Data3 = PrefTallyR3Data(0, r3Data.rankingsDecryptedC1.tail.head :: r3Data.rankingsDecryptedC1.tail)
    require(badR1Data3.validate(ctx, pubKey, ciphertexts) == false)

    val badR1Data4 = PrefTallyR3Data(0, r3Data.rankingsDecryptedC1.tail)
    require(badR1Data4.validate(ctx, pubKey, ciphertexts) == false)
  }

  test("PrefTallyR3Data serialization") {
    val vectors = (0 until 10).toList.map(_ => createRandomDecryptionShares(ctx, pubKey, privKey, 5))
    val r3Data = PrefTallyR3Data(55, vectors.map(_._2))
    val bytes = r3Data.bytes
    val restoredR3Data = PrefTallyR3DataSerializer.parseBytes(bytes, Option(group)).get

    require(restoredR3Data.issuerID == 55)
    require(restoredR3Data.rankingsDecryptedC1.size == 10)
    restoredR3Data.rankingsDecryptedC1.foreach(v => require(v.size == 5))
    require(restoredR3Data.validate(ctx, pubKey, vectors.map(_._1)))
  }
}
