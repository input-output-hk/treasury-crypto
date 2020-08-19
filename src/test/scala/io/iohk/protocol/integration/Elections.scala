package io.iohk.protocol.integration

import io.iohk.core.crypto.encryption.PubKey
import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen.CommitteeMember
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.voting.approval._
import io.iohk.protocol.voting.approval.multi_delegation.{DelegatedMultiDelegVote, DirectMultiDelegVote, MultiDelegExpertBallot, MultiDelegPrivateStakeBallot, MultiDelegPublicStakeBallot, MultiDelegVoterBallot}

import scala.util.Try

trait Elections[VBALLOT, EBALLOT, CTX, RES] {

  def runVoting(sharedPubKey: PubKey): (Seq[VBALLOT], Seq[EBALLOT])

  def runTally(committeeMembers: Seq[CommitteeMember],
               voterBallots: Seq[VBALLOT],
               expertBallots: Seq[EBALLOT],
               dkgR1DataAll: Seq[R1Data]): RES

  def verify(tallyRes: RES): Boolean

  def getContext: CTX
}

