package io.iohk.protocol.keygen_2_0.NIZKs

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.NIZKs.CorrectCiphertextsMapping.{Statement, Witness}
import io.iohk.protocol.keygen_2_0.dlog_encryption.DLogEncryption
import org.scalatest.FunSuite

class CorrectCiphertextsMappingTests extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group
  private val n = dlogGroup.groupOrder
  private val g = dlogGroup.groupGenerator

  private val drng = new FieldElementSP800DRNG(dlogGroup.createRandomNumber.toByteArray, n)

  import context.group

  test("CorrectCiphertextsMapping"){
    val encryptionsNum = 20

    val keyPairs = for(_ <- 0 until encryptionsNum) yield encryption.createKeyPair.get
    val plaintexts = for(_ <- 0 until encryptionsNum) yield drng.nextRand

    val encryptions = plaintexts.zip(keyPairs).map{
      p_kp =>
        val (plaintext, keyPair) = p_kp
        DLogEncryption.encrypt(plaintext, keyPair._2)
    }

    val keyPairCommon = encryption.createKeyPair.get
    val encryptionsCommon = plaintexts.map{
      p => DLogEncryption.encrypt(p, keyPairCommon._2)
    }

    for(i <- 0 until encryptionsNum) {
      val pubKeyFrom = keyPairs(i)._2
      val pubKeyTo = keyPairCommon._2
      val ctFrom = encryptions(i).get
      val ctTo = encryptionsCommon(i).get

      val ccm = CorrectCiphertextsMapping(pubKeyFrom, pubKeyTo, Statement(ctFrom._1, ctTo._1), dlogGroup)
      val proof = ccm.prove(Witness(ctFrom._2, ctTo._2))

      assert(ccm.verify(proof))
    }
  }
}
