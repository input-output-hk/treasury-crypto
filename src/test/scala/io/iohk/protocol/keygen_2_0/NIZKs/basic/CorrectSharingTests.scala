package io.iohk.protocol.keygen_2_0.NIZKs.basic

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.datastructures.Share
import io.iohk.protocol.common.dlog_encryption.{DLogCiphertext, DLogEncryption}
import io.iohk.protocol.common.encoding.BaseCodec
import io.iohk.protocol.common.math.{LagrangeInterpolation, Polynomial}
import org.scalatest.FunSuite

import scala.util.Try

class CorrectSharingTests extends FunSuite  {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group
  private val n = dlogGroup.groupOrder
  private val g = dlogGroup.groupGenerator
  private val drng = new FieldElementSP800DRNG(dlogGroup.createRandomNumber.toByteArray, n)

  private val sharesNum = 10
  private val threshold = (sharesNum * 0.5).toInt
  private val evaluation_points = for(point <- 1 to sharesNum) yield point

  import context.group

  private def shareSecret(secret: BigInt): Seq[Share] = {
    val poly = Polynomial(dlogGroup, threshold - 1, secret)
    LagrangeInterpolation.getShares(poly, evaluation_points)
  }

  private def encrypt(shares: Seq[Share], pubKey: PubKey): Try[(Seq[(DLogCiphertext, Int)], BigInt)] = Try {

    val sharesEnc = shares.map{ share =>
      DLogEncryption.encrypt(share.value, pubKey).get
    }
    // Composing zm values from the randomnesses that were used during the shares fragments encryption
    val zmSeq = sharesEnc.map(_._2).map{ zmEncoded =>
      zmEncoded.R.zipWithIndex.foldLeft(BigInt(0)){ (acc, r_i) =>
        val (r, i) = r_i
        (acc + r * BaseCodec.defaultBase.pow(i)).mod(n)
      }
    }
    // Computing a value of initial randomness z as it would be reconstructed by random values zm
    val z = zmSeq.zip(evaluation_points).take(threshold).foldLeft(BigInt(0)){(acc, zm_point) =>
      val (zm, point) = zm_point
      val L = LagrangeInterpolation.getLagrangeCoeff(group, point, evaluation_points.take(threshold))
      (acc + L * zm).mod(n)
    }
    (sharesEnc.map(_._1).zip(evaluation_points), z)
  }

  test("CorrectSharing"){
    val (privKey, pubKey) = encryption.createKeyPair.get
    val s  = drng.nextRand
    val s_ = drng.nextRand

    val D = dlogGroup.multiply(
      dlogGroup.exponentiate(g, s).get,
      dlogGroup.exponentiate(pubKey, s_).get).get

    val shares = shareSecret(s)
    val (sharesEncWithPoints, z) = encrypt(shares, pubKey).get

    val cs = CorrectSharing(pubKey, dlogGroup)
    val proof = cs.prove(CorrectSharing.Witness(s, s_, z))

    assert(cs.verify(proof, CorrectSharing.Statement(sharesEncWithPoints, D, threshold)))
  }
}
