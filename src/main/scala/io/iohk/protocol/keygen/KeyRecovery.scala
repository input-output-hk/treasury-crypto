package io.iohk.protocol.keygen

import io.iohk.core.crypto.encryption.{KeyPair, PrivKey, PubKey}
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round5_1.ViolatorsSharesData
import io.iohk.protocol.{CryptoContext, Identifier}

import scala.util.Try

/**
  * Provides basic functionality for restoration of private keys of failed committee members
  */
class KeyRecovery(ctx: CryptoContext, cmIdentifier: Identifier[Int]) {

  def restorePrivateKeys(disqualifiedCommitteeIds: Set[Int],
                         violatorsSharesData: Seq[ViolatorsSharesData]): Try[Map[PubKey, PrivKey]] = Try {
    val restoredKeys = disqualifiedCommitteeIds.map{ id =>
      val pubKey = cmIdentifier.getPubKey(id).get
      val recoveryShares = violatorsSharesData.map(_.violatorsShares.find(_._1 == id).map(_._2)).flatten

      // note that there should be at least t/2 recovery shares, where t is the size of the committee, otherwise recovery will fail
      val privKey = DistrKeyGen.recoverPrivateKeyByOpenedShares(ctx, cmIdentifier.pubKeys.size, recoveryShares, Some(pubKey)).get
      (pubKey -> privKey)
    }.toMap

    restoredKeys
  }

  def prepareRecoverySharesData(committeeMemberKey: KeyPair,
                                disqualifiedCommitteeIds: Set[Int],
                                dkgR1DataAll: Seq[R1Data]): Try[ViolatorsSharesData] = Try {

    val myId = cmIdentifier.getId(committeeMemberKey._2).get
    if (disqualifiedCommitteeIds.nonEmpty) {
      // we need to act only if there are committee members that failed during Tally Round 1
      val recoveryShares = disqualifiedCommitteeIds.toSeq.map { id =>
        val recoveryShare = DistrKeyGen.generateRecoveryKeyShare(ctx, cmIdentifier,
          committeeMemberKey, cmIdentifier.getPubKey(id).get, dkgR1DataAll).get
        (id, recoveryShare)
      }
      new ViolatorsSharesData(myId, recoveryShares)
    } else {
      // there are no failed memebers, so nothing to add
      new ViolatorsSharesData(myId, Seq())
    }
  }

  def verifyRecoverySharesData(committePubKey: PubKey,
                               violatorsSharesData: ViolatorsSharesData,
                               disqualifiedCommitteeIds: Set[Int],
                               dkgR1DataAll: Seq[R1Data]): Try[Unit] = Try {
    val committeID = cmIdentifier.getId (committePubKey).get
    require (violatorsSharesData.issuerID == committeID, "Committee identifier in TallyR2Data is invalid")
    require (violatorsSharesData.violatorsShares.map (_._1).toSet == disqualifiedCommitteeIds, "Unexpected set of recovery shares")

    violatorsSharesData.violatorsShares.foreach { s =>
      val violatorPubKey = cmIdentifier.getPubKey (s._1).get
      require (DistrKeyGen.validateRecoveryKeyShare (ctx, cmIdentifier, committePubKey, violatorPubKey, dkgR1DataAll, s._2).isSuccess)
    }
  }
}
