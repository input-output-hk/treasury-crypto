package io.iohk.protocol.keygen_him

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.datastructures.Share
import io.iohk.protocol.common.him.HIM
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.common.utils.Serialization.serializationIsCorrect
import io.iohk.protocol.keygen_him.datastructures.{R1DataSerializer, R2DataSerializer}
import org.scalatest.FunSuite

import scala.util.Random

class KeyGenTests extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val g = context.group.groupGenerator

  import context.group

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  test("DKG_HIM_shares_encryption"){

    val partiesNum = Random.nextInt(20) + 20
    val allPartiesKeys = generateKeys(partiesNum)

    val params = SharingParameters(allPartiesKeys.map(_._2))
    val secret = context.group.createRandomNumber
    val polynomial = Polynomial(context.group, params.t - 1, secret)

    val shares = DKGenerator.getShares(polynomial, params.allIds.map(IdPointMap.toPoint))
    val encShares = DKGenerator.encryptShares(context, shares, params.keyToIdMap).map(_._1)

    val openedShares = allPartiesKeys.map{
      keyPair =>
        val (privKey, pubKey) = keyPair
        val receiverID = params.keyToIdMap.getId(pubKey).get

        val secretSharesForId = encShares.filter(_.receiverID == receiverID)
        val openedSharesForId = DKGenerator.decryptShares(context, secretSharesForId, privKey)

        assert(openedSharesForId.isSuccess && openedSharesForId.get.size == 1)

        val openedShare = openedSharesForId.get.head
        assert(shares.contains(openedShare))

        openedShare
    }

    assert(openedShares.size == shares.size)
    assert(DKGenerator.reconstructSecret(context, openedShares.take(params.t)) == secret)
  }

  test("DKG_HIM_correct_run"){

    val generatorsNum = 10
    val generatorsKeys = generateKeys(generatorsNum)

    val alphas = generatorsKeys.map(_ => group.createRandomNumber)
    val betas  = generatorsKeys.map(_ => group.createRandomNumber)

    val generators = generatorsKeys.map(keyPair =>
      DKGenerator(
        context,
        Seq(crs),
        keyPair,
        generatorsKeys.map(_._2),
        alphas,
        betas
      )
    )

    val r1Data = generators.map(_.round1())
    val r2Data = generators.map(_.round2(r1Data))
    val complaints = generators.map(_.round3(r2Data))

    // Serialization tests
    assert(serializationIsCorrect(r1Data, R1DataSerializer))
    assert(serializationIsCorrect(r2Data, R2DataSerializer))

    // The protocol is running without any deviations so there should no be complaints
    assert(complaints.forall(_.isEmpty))

    // Get Global Public Keys (all g^partialSK's multiplied by HIM)
    val gpks = generators.map(_.globalPubKeys())
    assert(gpks.forall(_ == gpks.head))

    // Reconstructing the Global Secret Keys (generated via HIM multiplication) by shares from all parties
    val sharesPerGSK = generators.map(
      g => g.getPartialSKs().map(Share(IdPointMap.toPoint(g.ownID), _)) // each party has a share per GSK; all it's shares are in the same point
    ).transpose // now each row contains a set of all shares per corresponding GSK
    val gsks_reconstructed = sharesPerGSK.map(DKGenerator.reconstructSecret(context, _))

    // Check that the reconstructed GSKs are the same as the GSKs computed directly from partial SKs via HIM multiplication
    val him = HIM(alphas, betas)
    val gsks = him.mul(generators.sortBy(_.ownID).map(_.partialSK)) // Partial SKs should be ordered by parties IDs
    assert(gsks_reconstructed == gsks)

    // Check that the public keys built from reconstructed GSKs are the same as the generated GPKs
    val gpks_reconstructed = gsks_reconstructed.map(g.pow(_).get) // GPK = g^GSK
    assert(gpks_reconstructed == gpks.head)
  }
}
