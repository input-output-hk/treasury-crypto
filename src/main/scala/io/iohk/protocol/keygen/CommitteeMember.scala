package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round2.R2Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.datastructures.round4.R4Data
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1Data
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2Data
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}

import scala.util.Try

/**
  * CommitteeMember is strictly for testing purposes at this point. It is a wrapper for the functionality performed
  * by a committee member. It wraps 5-round distributed key generation.
  * TODO: consider to refactor CommitteeMember class for being a full-fledged wrapper for a committee member functionality
  *
  * @param ctx
  * @param transportKeyPair key pair of this committee member
  *                         TODO: here transportKeyPair serves also as a key pair for generating shared key.
  *                         TODO: It is ok for testing but not the case for real world.
  * @param committeeMembersPubKeys public keys of all committee members
  * @param roundsData
  */
class CommitteeMember(val ctx: CryptoContext,
                      val transportKeyPair: KeyPair,
                      val committeeMembersPubKeys: Seq[PubKey],
                      roundsData: RoundsData = RoundsData()) {
  import ctx.{group, hash}

  val memberIdentifier = new CommitteeIdentifier(committeeMembersPubKeys)

  // TODO: transport key pair serves also as a key pair for generating shared key. Originally these pairs were designed to be different.
  val secretKey = transportKeyPair._1
  val publicKey = transportKeyPair._2

  // DistrKeyGen instance is used to run distributed key generation protocol
  val seed = hash.hash(secretKey.toByteArray ++ "DKG Seed".getBytes) // TODO: secretKey should not be used to extract seed
  protected val dkg = new DistrKeyGen(ctx, transportKeyPair, secretKey, seed, committeeMembersPubKeys, memberIdentifier, roundsData)
  var dkgViolatorsKeys: Option[Map[PubKey, Option[PrivKey]]] = None

  val ownId: Int = dkg.ownID

  def doDKGRound1(): Try[R1Data] = Try {
    dkg.doRound1().get
  }

  def doDKGRound2(r1Data: Seq[R1Data]): Try[R2Data] = Try {
    dkg.doRound2(r1Data).get
  }

  def doDKGRound3(r2Data: Seq[R2Data]): Try[R3Data] = Try {
    dkg.doRound3(r2Data).get
  }

  def doDKGRound4(r3Data: Seq[R3Data]): Try[R4Data] = Try {
    dkg.doRound4(r3Data).get
  }

  def doDKGRound5_1(r4Data: Seq[R4Data]): Try[R5_1Data] = Try {
    dkg.doRound5_1(r4Data).get
  }

  def doDKGRound5_2(r5_1Data: Seq[R5_1Data]): Try[R5_2Data] = Try {

    val data = dkg.doRound5_2(r5_1Data).get

    var violatorKeys: Map[PubKey, Option[PrivKey]] = dkg.getAllDisqualifiedIds.map(memberIdentifier.getPubKey(_).get -> None).toMap
    data.violatorsSecretKeys.foreach{ sk =>
      val violatorPubKey = memberIdentifier.getPubKey(sk.ownerID).get
      val violatorPrivKey = BigInt(sk.secretKey)
      assert(violatorPubKey == group.groupGenerator.pow(violatorPrivKey).get)
      violatorKeys += violatorPubKey -> Some(violatorPrivKey)
    }

    dkgViolatorsKeys = Some(violatorKeys)

    data
  }
}