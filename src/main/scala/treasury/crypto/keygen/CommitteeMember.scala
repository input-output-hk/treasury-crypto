package treasury.crypto.keygen

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.keygen.datastructures.round1.{R1Data, SecretShare}
import treasury.crypto.keygen.datastructures.round2.{ComplaintR2, R2Data}
import treasury.crypto.keygen.datastructures.round3.R3Data
import treasury.crypto.keygen.datastructures.round4.{ComplaintR4, OpenedShare, R4Data}
import treasury.crypto.keygen.datastructures.round5_1.R5_1Data
import treasury.crypto.keygen.datastructures.round5_2.R5_2Data
import treasury.crypto.voting.Tally
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.ballots.Ballot

import scala.util.Try


class CommitteeMember(val cs: Cryptosystem,
                      val h: Point,
                      val transportKeyPair: KeyPair,
                      val committeeMembersPubKeys: Seq[PubKey],
                      roundsData: RoundsData = RoundsData()) {

//  // SimpleIdentifier is useful for debugging purposes, but in real it's better to not rely on an order stability of the externally provided public keys
//  val memberIdentifier = SimpleIdentifier(committeeMembersPubKeys)

  // Here public keys are forcibly sorted, thus their indices, which plays the role of member ID, will be always the same for the same set of public keys
  val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

  val secretKey = transportKeyPair._1
  val publicKey = transportKeyPair._2

  // DistrKeyGen depends on common system parameters, committee member's keypair and set of committee members. It encapsulates the shared key generation logic.
  private val dkg = new DistrKeyGen(cs, h, transportKeyPair, secretKey, committeeMembersPubKeys, memberIdentifier, roundsData)

  val ownId: Integer = dkg.ownID
  var dkgViolatorsSKs: Array[BigInteger] = Array[BigInteger]()
  var dkgViolatorsIds: Set[Integer] = Set()
  var decryptionViolatorsIds: Set[Int] = Set()
  var delegations: Option[Seq[Element]] = None

  def setKeyR1(): R1Data = {
    dkg.doRound1() match {
      case Some(data) => data
      case None =>
        println("doRound1 returned None")
        R1Data(12345, Array[Array[Byte]](), Array[SecretShare](), Array[SecretShare]())
    }
  }

  def setKeyR2(r1Data: Seq[R1Data]): R2Data = {
    dkg.doRound2(r1Data) match {
      case Some(data) => data
      case None =>
        println("doRound2 returned None")
        R2Data(12345, Array[ComplaintR2]())
    }
  }

  def setKeyR3(r2Data: Seq[R2Data]): R3Data = {
    dkg.doRound3(r2Data) match {
      case Some(data) => data
      case None =>
        println("doRound3 returned None")
        R3Data(12345, Array[Array[Byte]]())
    }
  }

  def setKeyR4(r3Data: Seq[R3Data]): R4Data = {
    dkg.doRound4(r3Data) match {
      case Some(data) => data
      case None =>
        println("doRound4 returned None")
        R4Data(12345, Array[ComplaintR4]())
    }
  }

  def setKeyR5_1(r4Data: Seq[R4Data]): R5_1Data = {

    dkg.doRound5_1(r4Data) match {
      case Some(data) => data
      case None =>
        println("doRound5_1 returned None")
        R5_1Data(12345, Array[(Integer, OpenedShare)]())
    }
  }

  def setKeyR5_2(r5_1Data: Seq[R5_1Data]): R5_2Data = {

    val data = dkg.doRound5_2(r5_1Data).get

    dkgViolatorsSKs = data.violatorsSecretKeys.map(sk => new BigInteger(sk.secretKey))
    dkgViolatorsIds = data.violatorsSecretKeys.map(_.ownerID).toSet

    data
  }

  // DecryptionManager depends on committee member's secret key and set of ballots. It encapsulates the tally decryption logic.
  //
  private var decryptor: Option[DecryptionManager] = None

  private def getSkShares(submittersIDs: Seq[Integer]): KeyShares =
  {
    val membersIds = committeeMembersPubKeys.map(memberIdentifier.getId(_).get.intValue())
    val activeMembersIds = membersIds.diff(dkgViolatorsIds.toSeq).diff(decryptionViolatorsIds.toSeq)
    val absenteesIds = activeMembersIds.diff(submittersIDs).filter(_ != ownId)

    decryptionViolatorsIds ++= absenteesIds.toSet

    KeyShares(ownId, absenteesIds.map(x => SKShare(x, dkg.getShare(x).getOrElse(new BigInteger("")))))
  }

  def recoverDelegationsC1(skShares: Seq[KeyShares]): Seq[Seq[Point]] = {
    val decryptionViolatorsSKs = reconstructSecretKeys(skShares)
    decryptor.get.decryptVector(decryptionViolatorsSKs, decryptor.get.delegationsSum.map(_._1))
  }

  def recoverChoicesC1(skShares: Seq[KeyShares], choicesSum: Seq[Ciphertext]): Seq[Seq[Point]] = {
    val decryptionViolatorsSKs = reconstructSecretKeys(skShares)
    decryptor.get.decryptVector(decryptionViolatorsSKs, choicesSum.map(_._1))
  }

  def reconstructSecretKeys(skShares: Seq[KeyShares]): Array[BigInteger] = {
    val decryptionViolatorsShares = skShares.map(
      member =>
        member.keyShares.map(
          share =>
            (share.ownerID, OpenedShare(member.issuerID, HybridPlaintext(cs.infinityPoint, share.share.toByteArray)))
        )
    ).map(_.sortBy(_._1).map(_._2)).transpose

    decryptionViolatorsShares.map(LagrangeInterpolation.restoreSecret(cs, _, dkg.t)).toArray
  }

  def decryptTallyR1(ballots: Seq[Ballot]): C1Share =
  {
    // Initialization of the decryptor
    decryptor = Some(new DecryptionManager(cs, ballots, dkg.t))
    decryptor.get.decryptC1ForDelegations(ownId, 0, secretKey)
  }

  def keysRecoveryR1(c1ForDelegationsIn: Seq[C1Share]): KeyShares =
  {
    val c1ForDelegations = c1ForDelegationsIn
      .filter(x => !dkgViolatorsIds.contains(x.issuerID))
      //.filter(c1 => decryptor.validateDelegationsC1(c1)) // TODO: do we really need validation here? // this should happen externally

    getSkShares(c1ForDelegations.map(_.issuerID))
  }

  def decryptTallyR2(c1ForDelegationsIn: Seq[C1Share], skSharesIn: Seq[KeyShares]): C1Share =
  {
    val c1ForDelegations = c1ForDelegationsIn.filter(
      x =>
        !dkgViolatorsIds.contains(x.issuerID) && !decryptionViolatorsIds.contains(x.issuerID))

    val skShares = skSharesIn.filter(
      x =>
        !dkgViolatorsIds.contains(x.issuerID) && !decryptionViolatorsIds.contains(x.issuerID))

    val d = decryptor.get

    val delegationsC1 = c1ForDelegations.map(_.decryptedC1.map(_._1))
    val dkgViolatorsC1 = d.decryptVector(dkgViolatorsSKs, d.delegationsSum.map(_._1))
    val decryptionViolatorsC1 = recoverDelegationsC1(skSharesIn)
    delegations = Some(d.computeDelegations(delegationsC1 ++ dkgViolatorsC1 ++ decryptionViolatorsC1))

    d.decryptC1ForChoices(ownId, 0, secretKey, delegations.get)
  }

  def keysRecoveryR2(c1ForChoicesIn: Seq[C1Share]): KeyShares =
  {
    val c1ForChoices = c1ForChoicesIn
      .filter(
        x =>
          !dkgViolatorsIds.contains(x.issuerID) && !decryptionViolatorsIds.contains(x.issuerID))
      //.filter(c1 => decryptor.validateChoicesC1(c1, c1ForDelegationsIn)) // this should happen externally

    getSkShares(c1ForChoices.map(_.issuerID))
  }

  def decryptTallyR3(c1ForChoicesIn: Seq[C1Share], delegSkSharesIn: Seq[KeyShares], choicesSkSharesIn: Seq[KeyShares]): Result =
  {
    val c1ForChoices = c1ForChoicesIn.filter(
      x =>
      !dkgViolatorsIds.contains(x.issuerID) && !decryptionViolatorsIds.contains(x.issuerID))

    val d = decryptor.get

    val choicesSum = d.computeChoicesSum(delegations.get)
    val dkgViolatorsC1 = d.decryptVector(dkgViolatorsSKs, choicesSum.map(_._1))
    val decryptionViolatorsC1 = recoverChoicesC1(choicesSkSharesIn, choicesSum) ++ recoverChoicesC1(delegSkSharesIn, choicesSum)

    val allChoicesC1 = dkgViolatorsC1 ++ decryptionViolatorsC1 ++ c1ForChoices.map(_.decryptedC1.map(_._1))

    Tally.countVotes(cs, d.votersBallots ++ d.expertsBallots, allChoicesC1, delegations.get).get
  }
}