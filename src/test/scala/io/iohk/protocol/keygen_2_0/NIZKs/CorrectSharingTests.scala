package io.iohk.protocol.keygen_2_0.NIZKs

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.PubKey
import io.iohk.core.crypto.primitives.numbergenerator.FieldElementSP800DRNG
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.datastructures.Share
import io.iohk.protocol.keygen_2_0.dlog_encryption.{DLogCiphertext, DLogEncryption}
import io.iohk.protocol.keygen_2_0.math.{LagrangeInterpolation, Polynomial}
import org.scalatest.FunSuite

import scala.util.{Success, Try}

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
    val poly = new Polynomial(context, threshold - 1, secret, drng)
    LagrangeInterpolation.getShares(poly, evaluation_points)
  }

  private def encrypt(shares: Seq[Share], randomness: BigInt, pubKey: PubKey): Try[Seq[(DLogCiphertext, Int)]] = Try {
    val randomnessShares = shareSecret(randomness)

    val sharesEnc = shares.zip(randomnessShares).map{ share_randomness =>
      val (share, randomness) = share_randomness
      DLogEncryption.encrypt(share.value, randomness.value, pubKey).get._1
    }
    sharesEnc.zip(evaluation_points).map(s_p => (s_p._1, s_p._2))
  }

  private def encrypt(shares: Seq[Share], pubKey: PubKey): Option[(Seq[(DLogCiphertext, Int)], BigInt)] = {
    for(_ <- 0 until 10){ // 10 attempts to encrypt with a new randomness
      var randomness = drng.nextRand // initial randomness; its shares are randomness values for the 's' shares encryption
      encrypt(shares, randomness, pubKey) match {
        case Success(res) => return Some((res, randomness))
        case _            => randomness = drng.nextRand
      }
    }
    None
  }

  private def testCorrectSharing(){
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

  test("CorrectSharing"){
    for(_ <- 0 until 100) {
      testCorrectSharing()
    }
  }
}
