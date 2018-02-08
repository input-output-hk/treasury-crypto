package treasury.crypto.keygen

import java.math.BigInteger

import treasury.crypto.core._
import treasury.crypto.keygen.datastructures.C1Share
import treasury.crypto.voting.Tally
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.ballots.Ballot


class CommitteeMember(val cs: Cryptosystem,
                      val h: Point,
                      val transportKeyPair: KeyPair,
                      val committeeMembersPubKeys: Seq[PubKey]) {

  // DistrKeyGen depends on common system parameters, committee member's keypair and set of committee members. It encapsulates the shared key generation logic.
  //
  private val dkg = new DistrKeyGen(cs, h, transportKeyPair, committeeMembersPubKeys)

  val secretKey = cs.getRand
  val publicKey = cs.basePoint.multiply(secretKey).normalize()
  val ownId: Integer = dkg.ownID

  var dkgViolatorsSKs: Array[BigInteger] = Array[BigInteger]()
  var dkgViolatorsIds: Set[Integer] = Set()
  var decryptionViolatorsIds: Set[Int] = Set()
  var delegations: Option[Seq[Element]] = None

  val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

  def setKeyR1(): R1Data = {
    dkg.doRound1(secretKey.toByteArray)
  }

  def setKeyR2(r1Data: Seq[R1Data]): R2Data = {
    dkg.doRound2(r1Data)
  }

  def setKeyR3(r2Data: Seq[R2Data]): R3Data = {
    dkg.doRound3(r2Data)
  }

  def setKeyR4(r3Data: Seq[R3Data]): R4Data = {
    dkg.doRound4(r3Data)
  }

  def setKeyR5_1(r4Data: Seq[R4Data]): R5_1Data = {
    dkg.doRound5_1(r4Data)
  }

  def setKeyR5_2(r5_1Data: Seq[R5_1Data]): R5_2Data = {

    val data = dkg.doRound5_2(r5_1Data)

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

    KeyShares(ownId, absenteesIds.map(x => SKShare(x, dkg.getShare(x))))
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

//  def recoverC1SharesR1(skSharesIn: Seq[KeyShares]): Seq[C1Share] = {
//    val skShares = skSharesIn.filter(x => !dkgViolatorsIds.contains(x.issuerID))
//    val decryptionViolatorsSKs = Tally.reconstructSecretKeys(cs, skShares, dkg.t)
//    val decryptionViolatorsC1 = decryptionViolatorsSKs.map(sk => delegationsSum.map(_._1.multiply(sk)))
//    val dkgViolatorsC1 = dkgViolatorsSKs.map(sk => delegationsSum.map(_._1.multiply(sk)))
//  }

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
    val decryptionViolatorsC1 = d.recoverDelegationsC1(skSharesIn)
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
    val decryptionViolatorsC1 = d.recoverChoicesC1(choicesSkSharesIn, choicesSum) ++ d.recoverChoicesC1(delegSkSharesIn, choicesSum)

    val allChoicesC1 = dkgViolatorsC1 ++ decryptionViolatorsC1 ++ c1ForChoices.map(_.decryptedC1.map(_._1))

    d.decryptTally(allChoicesC1, delegations.get)
  }
}