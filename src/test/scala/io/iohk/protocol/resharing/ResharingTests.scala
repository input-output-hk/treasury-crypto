package io.iohk.protocol.resharing

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.KeyPair
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.common.math.Polynomial
import io.iohk.protocol.keygen_him.{DKGenerator, IdPointMap, SharingParameters}
import org.scalatest.FunSuite

class ResharingTests extends FunSuite {

  private val context = new CryptoContext(None)

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  def corruptResharings(resharings: Seq[ResharingData], numOfPartiesToCorrupt: Int): Seq[ResharingData] = {
    assert(numOfPartiesToCorrupt <= resharings.length)
    resharings.zipWithIndex.map{
      case (d, i) =>
        if (i < numOfPartiesToCorrupt){
          // Removing the commitment of a_0 coefficient in each SharedShare of a current party
          ResharingData(
            d.senderID,
            d.sharedShares.map(s => SharedShare(s.encShares, s.coeffsCommitments.drop(1)))
          )
        } else { d }
    }
  }

  def initialize(partiesNum: Int): (Seq[Resharing], Int, Seq[KeyPair], SharingParameters) = {
    val adversariesMaxNum = partiesNum / 2 - 1

    val allPartiesKeys = generateKeys(partiesNum)
    val allPartiesPubKeys = allPartiesKeys.map(_._2)
    val params = SharingParameters(allPartiesPubKeys)

    val receivingParties = allPartiesKeys.map(keyPair => Resharing(context, keyPair, allPartiesPubKeys))

    (receivingParties, adversariesMaxNum, allPartiesKeys, params)
  }

  def testResharing(withCorruptions: Boolean): Unit = {
    val partiesNum = 10 // assuming that the number of resharing parties and receiving parties is the same
    val (receivers, adversariesMaxNum, _, params) = initialize(partiesNum)
    val secretsNum = partiesNum - adversariesMaxNum // according to the HIM DKG the number of generated secrets available for usage is (n - t)

    val secrets = (0 until secretsNum).indices.map(_ => context.group.createRandomNumber)

    // Initial shares of the secrets
    val shares = secrets.map{ secret =>
      val polynomial = Polynomial(context.group, params.t - 1, secret)
      // Creating a set of shares per secret
      // NOTE: the resharing parties can have arbitrary IDs (relatively to receiving parties) so just using the range: (0 until partiesNum)
      DKGenerator.getShares(polynomial, (0 until partiesNum).map(IdPointMap.toPoint))
    }

    // Simulating resharing of the secrets by sharing the initial shares owned by corresponding virtual parties
    val resharings = shares.transpose.map{partyShares => // transposing to get shares of all secrets per party
      // Checking that all shares belong to the same party
      assert(partyShares.forall(_.point == partyShares.head.point))
      // ID of the virtual party (dealer relatively to the receiving parties) who shares the current share
      val dealerID = IdPointMap.toId(partyShares.head.point)
      // Virtual party gets a set of shares for it's share (i.e. reshares it's part of a secret)
      Resharing.getResharings(context, params, dealerID, partyShares.map(_.value))
    }

    // Receiving parties receive and validate the resharings and create complaints if needed
    val complaints = receivers.flatMap(_.receiveResharings(
      if(withCorruptions) corruptResharings(resharings, adversariesMaxNum)
      else resharings
    ))

    assert(
      if(withCorruptions) complaints.nonEmpty
      else complaints.isEmpty
    )

    // Getting new shares per receiving party
    val newShares = receivers.map(_.buildNewShares(complaints))
    assert(
      // Transposing to get shares of all parties per secret
      newShares.transpose.zip(secrets).forall{case (sharesPerSecret, secret) =>
        DKGenerator.reconstructSecret(context, sharesPerSecret.take(params.t)) == secret &&
        // Using a full set of shares to check that all new shares are consistent
        DKGenerator.reconstructSecret(context, sharesPerSecret) == secret
      }
    )
  }

  test("resharing"){
    testResharing(withCorruptions = false)
  }

  test("resharing_with_corruptions"){
    testResharing(withCorruptions = true)
  }
}
