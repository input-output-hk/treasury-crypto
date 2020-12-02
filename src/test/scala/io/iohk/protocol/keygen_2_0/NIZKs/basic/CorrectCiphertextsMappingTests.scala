package io.iohk.protocol.keygen_2_0.NIZKs.basic

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.dlog_encryption.DLogEncryption
import org.scalatest.FunSuite

class CorrectCiphertextsMappingTests extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group
  private val n = dlogGroup.groupOrder
  private val drng = new FieldElementSP800DRNG(dlogGroup.createRandomNumber.toByteArray, n)

  import context.group

  test("CorrectCiphertextsMapping"){

    import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectCiphertextsMapping.{Statement, Witness}

    val encryptionsNum = 20

    val publicKeys = for(_ <- 0 until encryptionsNum) yield encryption.createKeyPair.get._2
    val plaintexts = for(_ <- 0 until encryptionsNum) yield drng.nextRand

    val encryptions = plaintexts.zip(publicKeys).map{     // encryptions on different Public Keys
      p_pk =>
        val (plaintext, publicKey) = p_pk
        DLogEncryption.encrypt(plaintext, publicKey)
    }

    val publicKeyCommon = encryption.createKeyPair.get._2
    val encryptionsCommonPK = plaintexts.map{             // encryptions on the common Public Key
      plaintext => DLogEncryption.encrypt(plaintext, publicKeyCommon)
    }

    for(i <- 0 until encryptionsNum) {
      val pubKeyFrom = publicKeys(i)
      val pubKeyTo = publicKeyCommon
      val ctFrom = encryptions(i).get._1
      val ctTo = encryptionsCommonPK(i).get._1
      val rFrom = encryptions(i).get._2
      val rTo = encryptionsCommonPK(i).get._2
      val statement = Statement(ctFrom, ctTo)

      val proof = CorrectCiphertextsMapping(pubKeyFrom, pubKeyTo, statement, dlogGroup).prove(Witness(rFrom, rTo))
      assert(CorrectCiphertextsMapping(pubKeyFrom, pubKeyTo, statement, dlogGroup).verify(proof))
    }
  }

  test("CorrectCiphertextsMappingBatched"){

    import io.iohk.protocol.keygen_2_0.NIZKs.basic.CorrectCiphertextsMappingBatched.{Statement, Witness}

    val encryptionsNum = 20

    val publicKeys = for(_ <- 0 until encryptionsNum) yield encryption.createKeyPair.get._2
    val plaintexts = for(_ <- 0 until encryptionsNum) yield drng.nextRand

    val encryptions = plaintexts.zip(publicKeys).map{     // encryptions on different Public Keys
      p_pk =>
        val (plaintext, publicKey) = p_pk
        DLogEncryption.encrypt(plaintext, publicKey)
    }

    val publicKeyCommon = encryption.createKeyPair.get._2
    val encryptionsCommonPK = plaintexts.map{             // encryptions on the common Public Key
      plaintext => DLogEncryption.encrypt(plaintext, publicKeyCommon)
    }

    val pubKeysFrom = publicKeys
    val pubKeyTo = publicKeyCommon
    val ctsFrom = encryptions.map(_.get._1)
    val ctsTo = encryptionsCommonPK.map(_.get._1)
    val rsFrom = encryptions.map(_.get._2)
    val rsTo = encryptionsCommonPK.map(_.get._2)
    val statement = Statement(ctsFrom, ctsTo)

    val proof = CorrectCiphertextsMappingBatched(pubKeysFrom, pubKeyTo, statement, dlogGroup).prove(Witness(rsFrom, rsTo))
    assert(CorrectCiphertextsMappingBatched(pubKeysFrom, pubKeyTo, statement, dlogGroup).verify(proof))
  }
}
