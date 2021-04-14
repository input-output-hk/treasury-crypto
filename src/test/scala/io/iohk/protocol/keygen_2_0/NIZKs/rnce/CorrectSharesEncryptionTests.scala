package io.iohk.protocol.keygen_2_0.NIZKs.rnce

import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.datastructures.Share
import io.iohk.protocol.keygen_2_0.math.{LagrangeInterpolation, Polynomial}
import io.iohk.protocol.keygen_2_0.rnce_encryption
import io.iohk.protocol.keygen_2_0.rnce_encryption.RncePubKey
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RnceCrsLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.{RnceBatchedEncryption, RnceParams}
import io.iohk.protocol.keygen_2_0.rnce_encryption.batched.data.{RnceBatchedCiphertext, RnceBatchedRandomness}
import org.scalatest.FunSuite

import scala.util.Try

class CorrectSharesEncryptionTests extends FunSuite  {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group
  private val n = dlogGroup.groupOrder
  private val drng = new FieldElementSP800DRNG(dlogGroup.createRandomNumber.toByteArray, n)

  private val sharesNum = 20
  private val threshold = (sharesNum * 0.5).toInt
  private val evaluation_points = {
    for (point <- 1 to sharesNum) yield point
  }.reverse

  private val alpha = dlogGroup.createRandomNumber
  private val rnce_crs = RnceCrsLight(g1 = crs, g2 = dlogGroup.exponentiate(crs, alpha).get)

  private val cse_crs = CorrectSharesEncryption.CRS(rnce_crs, dlogGroup.createRandomGroupElement.get)

  import context.group

  private def shareSecret(secret: BigInt): (Seq[Share], Polynomial) = {
    val poly = Polynomial(dlogGroup, threshold - 1, secret)
    (LagrangeInterpolation.getShares(poly, evaluation_points), poly)
  }

  private def encrypt(shares: Seq[Share], pubKey: Seq[RncePubKey]): Try[Seq[(RnceBatchedCiphertext, RnceBatchedRandomness)]] = Try {
    // Encrypting shares on the corresponding public keys of receivers
    shares.zip(pubKey).map{ share_pk =>
      val (share, pk) = share_pk
      RnceBatchedEncryption.encrypt(pk, share.value, rnce_crs).get
    }
  }

  test("CorrectSharesEncryptionDkg"){
    val pubKeys = for(_ <- 0 until sharesNum) yield { rnce_encryption.createRnceKeyPair(RnceParams(rnce_crs)).get._2 }

    val s  = drng.nextRand
    val s_ = drng.nextRand

    val (shares1, f1) = shareSecret(s)
    val (shares2, f2) = shareSecret(s_)

    val cts_r__1 = encrypt(shares1, pubKeys).get
    val cts_r__2 = encrypt(shares2, pubKeys).get

    val ct1_ct2_seq = cts_r__1.map(_._1).zip(cts_r__2.map(_._1))
    val r1_r2_seq = cts_r__1.map(_._2).zip(cts_r__2.map(_._2))

    val statement = CorrectSharesEncryption.Statement(
      ct1_ct2_seq,
      pubKeys,
      evaluation_points
    )
    val witness = CorrectSharesEncryption.Witness(
      r1_r2_seq,
      f1.polynomial, f2.polynomial // passing all the coefficients of both polynomials
    )

    val proof = CorrectSharesEncryption(cse_crs, statement, dlogGroup).prove(witness)
    assert(CorrectSharesEncryption(cse_crs, statement, dlogGroup).verify(proof))
  }
}
