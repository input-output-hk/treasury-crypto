package io.iohk.protocol.keygen_2_0

import io.iohk.core.crypto.encryption
import io.iohk.core.crypto.encryption.{KeyPair, PubKey}
import io.iohk.protocol.keygen_2_0.datastructures.SecretShare
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.math.LagrangeInterpolation
import org.scalatest.FunSuite

import scala.util.Random

case class Node(context: CryptoContext,
                stake: Int = Random.nextInt(20) + 1, // influences committee size as well as nominatorsThreshold
                id: Int = Random.nextInt()) {

  private val longTermKeyPair = encryption.createKeyPair(context.group).get
  val longTermPubKey : PubKey = longTermKeyPair._2

  var nominatorOpt : Option[Nominator] = None
  var holderOpt : Option[Holder] = None

  def setNominator(params: NominationParameters) : Unit = {
    nominatorOpt = Nominator.create(context, longTermKeyPair, stake, params.thresholdCoeff, params.seed, params.longTermPubKeys)
  }

  def setHolder(nominations : Seq[Nomination]) : Unit = {
    holderOpt = Holder.create(context, longTermKeyPair, nominations)
  }

  def copy(): Node = {
    Node(context, stake, id)
  }
}

case class NominationParameters(seed: BigInt,
                                thresholdCoeff: BigInt,
                                longTermPubKeys: Seq[PubKey])

case class EpochContext(allNodes: Seq[Node] = Seq(),
                        holders: Seq[Node] = Seq(),
                        shares: Seq[SecretShare] = Seq()){
  assert(holders == allNodes.filter(_.holderOpt.nonEmpty))
}

class KeyGenTests extends FunSuite {

  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))

  private val nodesNum = 20
  private val epochsNum = 8
  // defines a nominating committee size (a well as a holding committee size)
  private val nominatorsThreshold = BigInt("08ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)

  def initializeParticipants(nodes: Seq[Node] = Seq()): Seq[Node] ={
    if(nodes.isEmpty){    // create nodes for the initial epoch
      for (_ <- 0 until nodesNum) yield {
        Node(context)
      }
    } else {              // re-initialize existing nodes
      nodes.map(_.copy())
    }
  }

  def setNominatingCommittee(allNodes: Seq[Node], params: NominationParameters): Seq[Node] ={
    allNodes.foreach(_.setNominator(params))
    allNodes.filter(_.nominatorOpt.nonEmpty)
  }

  def selectHoldingCommittee(nominators: Seq[Node]): Seq[Nomination] ={
    nominators.map(_.nominatorOpt.get.selectHolder())
  }

  def setHoldingCommittee(allNodes: Seq[Node], nominations: Seq[Nomination]): Seq[Node] ={
    allNodes.foreach(_.setHolder(nominations))
    allNodes.filter(_.holderOpt.nonEmpty)
  }

  def generate(holders: Seq[Node], nominationsNext: Seq[Nomination]): Seq[SecretShare] ={
    holders.flatMap(_.holderOpt.get.generate(nominationsNext))
  }

  def reshare(holders: Seq[Node], shares: Seq[SecretShare], nominationsNext: Seq[Nomination]): Seq[SecretShare] ={
    holders.flatMap(_.holderOpt.get.reshare(shares, nominationsNext))
  }

  def getCommonSecret(holders: Seq[Node]): BigInt = {
    holders.foldLeft(BigInt(0)){
      (sum, node) =>
        val partialSum = node.holderOpt.get.partialSecretsInitial.foldLeft(BigInt(0))((sum, ps) => sum + ps)
        (sum + partialSum).mod(context.group.groupOrder)
    }
  }

  def reconstructCommonSecret(holders: Seq[Node]): BigInt = {
    val all_shares = holders.flatMap(_.holderOpt.get.ownSharesSum)
    val all_points = all_shares.map(_._1)

    all_shares.foldLeft(BigInt(0)){
      (sum, point_share) =>
        val (point, share) = point_share
        val lambda = LagrangeInterpolation.getLagrangeCoeff(context, point, all_points)
        (sum + lambda * share).mod(context.group.groupOrder)
    }
  }

  def generateKeys(num: Int) : Seq[KeyPair] = for (_ <- 0 until num) yield encryption.createKeyPair(context.group).get

  test("sharing"){

    val testsNum = 10

    for(_ <- 0 until testsNum){
      val sharingMembersNum = Random.nextInt(20) + 20
      val holdingMembersNum = Random.nextInt(20) + 20
      val secret = BigInt(Random.nextInt().abs)

      val sharingCommitteeKeys = generateKeys(sharingMembersNum)
      val holdingCommitteeKeys = generateKeys(holdingMembersNum)

      val sharingCommitteeParams = SharingParameters(sharingCommitteeKeys.map(_._2))
      val holdingCommitteeParams = SharingParameters(holdingCommitteeKeys.map(_._2))

      val shares = Holder.shareSecret(context, 0, secret, sharingCommitteeParams, holdingCommitteeParams)

      val reconstructedSecret = Holder.reconstructSecret(context, shares.flatten, sharingCommitteeParams, holdingCommitteeParams)
      assert(reconstructedSecret.isSuccess && reconstructedSecret.get == secret)

      val sharesMinimalSetG = shares.take(holdingCommitteeParams.t)
      val sharesMinimalSet = sharesMinimalSetG.transpose.take(sharingCommitteeParams.t)
      val reconstructedSecretFromMinimalSet = Holder.reconstructSecret(context, sharesMinimalSet.flatten, sharingCommitteeParams, holdingCommitteeParams)
      assert(reconstructedSecretFromMinimalSet.isSuccess && reconstructedSecretFromMinimalSet.get == secret)
    }
  }

  test("shares_encryption"){

    val sharingMembersNum = Random.nextInt(20) + 20
    val holdingMembersNum = Random.nextInt(20) + 20
    val secret = BigInt(Random.nextInt().abs)

    val sharingCommitteeKeys = generateKeys(sharingMembersNum)
    val holdingCommitteeKeys = generateKeys(holdingMembersNum)

    val sharingCommitteeParams = SharingParameters(sharingCommitteeKeys.map(_._2))
    val holdingCommitteeParams = SharingParameters(holdingCommitteeKeys.map(_._2))

    val shares = Holder.shareSecret(context, 0, secret, sharingCommitteeParams, holdingCommitteeParams).flatten

    val holdingKeyIdMap = holdingCommitteeParams.keyToIdMap
    val allSecretShares = Holder.encryptShares(context, shares, holdingKeyIdMap)

    holdingCommitteeKeys.foreach{
      keyPair =>
        val (privKey, pubKey) = keyPair
        val receiverID = holdingKeyIdMap.getId(pubKey).get

        val secretSharesForId = allSecretShares.filter(_.receiverID == receiverID)
        val openedSharesForId = Holder.decryptShares(context, secretSharesForId, privKey)

        assert(openedSharesForId.isSuccess)

        openedSharesForId.get.foreach{
          openedShare =>
            assert(shares.contains(openedShare))
        }
    }
  }

  test("protocol"){

    var prevEpoch = EpochContext()
    var commonSecret = BigInt(0)

    for (epoch <- 0 until epochsNum){

      val allNodes = initializeParticipants(prevEpoch.allNodes)

      // epoch-related values
      val nominationParams = NominationParameters(
        seed = Random.nextInt(),
        thresholdCoeff = nominatorsThreshold,
        longTermPubKeys = allNodes.map(_.longTermPubKey)
      )

      val nominators = setNominatingCommittee(allNodes, nominationParams)
      val nominations = selectHoldingCommittee(nominators)

      val shares =
        epoch match {
          case 0 => Seq()
          case 1 => generate(prevEpoch.holders, nominations)
          case _ => reshare(prevEpoch.holders, prevEpoch.shares, nominations)
        }

      // Validate shares
      epoch match {
        case 0 =>
        case 1 => commonSecret = getCommonSecret(prevEpoch.holders)
        case _ => assert(commonSecret == reconstructCommonSecret(prevEpoch.holders))
      }
      prevEpoch = EpochContext(allNodes, setHoldingCommittee(allNodes, nominations), shares)

      println(s"${epoch}: n = ${nominators.size}, t = ${nominators.size / 2 + 1};")
    }
  }
}
