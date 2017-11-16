package treasury.crypto.keygen

import java.math.BigInteger

import treasury.crypto.core.{Cryptosystem, KeyPair, Point, PubKey}
import treasury.crypto.voting.Tally.Result
import treasury.crypto.voting.Ballot

class CommitteeMember(val cs: Cryptosystem,
                      val h: Point,
                      val transportKeyPair: KeyPair,
                      val committeeMembersPubKeys: Seq[PubKey]) {

  // DistrKeyGen depends on common system parameters, committee member's keypair and set of committee members. It encapsulates the shared key generation logic.
  //
  private val dkg = new DistrKeyGen(cs, h, transportKeyPair, committeeMembersPubKeys)

  val secretKey = cs.getRand
  val ownId: Integer = dkg.ownID

  var violatorsSecretKeys: Array[BigInteger] = null
  var violatorsIds: Set[Integer] = null

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

    violatorsSecretKeys = data.violatorsSecretKeys.map(sk => new BigInteger(sk.secretKey))
    violatorsIds = data.violatorsSecretKeys.map(_.ownerID).toSet

    data
  }

  // DecryptionManager depends on committee member's secret key and set of ballots. It encapsulates the tally decryption logic.
  //
  private var decryptor: DecryptionManager = null

  def decryptTallyR1(ballots: Seq[Ballot]): DelegationsC1 =
  {
    // Initialization of the decryptor
    decryptor = new DecryptionManager(cs, ownId, secretKey, violatorsSecretKeys, ballots)
    decryptor.decryptC1ForDelegations()
  }

  def decryptTallyR2(c1ForDelegationsIn: Seq[DelegationsC1]): ChoicesC1 =
  {
    val c1ForDelegations = c1ForDelegationsIn.filter(x => !violatorsIds.contains(x.issuerID))

    if(decryptor == null)
      throw UninitializedFieldError("decryptor is uninitialized. Run protocol from the 1-st round!")
    decryptor.decryptC1ForChoices(c1ForDelegations)
  }

  def decryptTallyR3(c1ForChoicesIn: Seq[ChoicesC1]): Result =
  {
    val c1ForChoices = c1ForChoicesIn.filter(x => !violatorsIds.contains(x.issuerID))

    if(decryptor == null)
      throw UninitializedFieldError("decryptor is uninitialized. Run protocol from the 1-st round!")
    decryptor.decryptTally(c1ForChoices)
  }
}
