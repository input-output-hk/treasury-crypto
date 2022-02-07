package io.iohk.protocol.keygen_him.NIZKs

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.commitment.PedersenCommitment
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.common.secret_sharing.ShamirSecretSharing.{encryptShares, getShares, IdPointMap, SharingParameters}
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.CorrectSharing
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.datastructures.ProofSerializer
import io.iohk.protocol.keygen_him.NIZKs.CorrectSharingNIZK.CorrectSharing.{Statement, Witness}
import org.scalatest.FunSuite

class CorrectSharingTests extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))

  import context.group

  private val g = group.groupGenerator
  private val h = CryptoContext.generateRandomCRS
  private val commitment = PedersenCommitment(g, h)

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  test("CorrectSharing"){

    val keysNum = 20
    val keys = generateKeys(keysNum)
    val pubKeys = keys.map(_._2)

    val params = SharingParameters(pubKeys)
    val secret = group.createRandomNumber

    val polynomial = Polynomial(group, params.t - 1, secret)
    val c_rand = polynomial.coeffs().map(c => (c, group.createRandomNumber))
    val coeffsCommitments = c_rand.map{ case(c, r) => commitment.get(c, r) }

    val shares = getShares(polynomial, params.allIds.map(IdPointMap.toPoint))
    val encShares_rand = encryptShares(context, shares, params)

    val st = Statement(coeffsCommitments, encShares_rand.map(_._1))
    val w = Witness(shares.zip(encShares_rand.map(_._2.R)), c_rand.map(_._2))

    val proof = CorrectSharing(h, pubKeys, st).prove(w)

    val proofParsed = ProofSerializer.parseBytes(proof.bytes, Some(group))
    assert(proofParsed.isSuccess && proofParsed.get == proof)

    assert(CorrectSharing(h, pubKeys, st).verify(proof))
  }
}
