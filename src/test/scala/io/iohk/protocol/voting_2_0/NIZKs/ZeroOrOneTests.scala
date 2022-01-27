package io.iohk.protocol.voting_2_0.NIZKs

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.elgamal.LiftedElGamalEnc
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.utils.Serialization.serializationIsCorrect
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.ZeroOrOne
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.ZeroOrOne.{Statement, Witness}
import io.iohk.protocol.voting_2_0.NIZKs.ZeroOrOneNIZK.datastructures.ProofSerializer
import org.scalatest.FunSuite

import scala.util.Random

class ZeroOrOneTests extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))

  import context.group

  test("ZeroOrOne"){
    val vecSize = 2
    val pubKey = encryption.createKeyPair(context.group).get._2

    val binaryVec = (0 until vecSize).map(_ => BigInt(Random.nextInt(2))) // random binary vector
    val encBinaryVec = binaryVec.map(LiftedElGamalEnc.encrypt(pubKey, _).get)

    val st = Statement(pubKey, encBinaryVec.map(_._1))
    val w = Witness(binaryVec, encBinaryVec.map(_._2))

    val proof = ZeroOrOne(st).prove(w)
    assert(serializationIsCorrect(Seq(proof), ProofSerializer))
    assert(ZeroOrOne(st).verify(proof))
  }

//  test("ZeroOrOne"){
//    val vecNum = 2
//    val vecSize = 2
//
//    val pubKey = encryption.createKeyPair(context.group).get._2
//
//    val binaryVecs = (0 until vecNum).map(_ =>
//      (0 until vecSize).map(_ => BigInt(Random.nextInt(2))) // random binary vector
//    )
//
//    val encBinaryVecs = binaryVecs.map(_.map(LiftedElGamalEnc.encrypt(pubKey, _)))
//  }
}
