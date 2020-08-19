package io.iohk.protocol.storage
import io.iohk.protocol.keygen.datastructures.round1.R1Data
import io.iohk.protocol.keygen.datastructures.round2.R2Data
import io.iohk.protocol.keygen.datastructures.round3.R3Data
import io.iohk.protocol.keygen.datastructures.round4.R4Data
import io.iohk.protocol.keygen.datastructures.round5_1.R5_1Data
import io.iohk.protocol.keygen.datastructures.round5_2.R5_2Data
import io.iohk.protocol.voting.approval.multi_delegation.tally.datastructures.{MultiDelegTallyR1Data, MultiDelegTallyR2Data, MultiDelegTallyR3Data, MultiDelegTallyR4Data}
import io.iohk.protocol.voting.approval.multi_delegation.{MultiDelegExpertBallot, MultiDelegVoterBallot}

import scala.util.Try

class RoundsDataInMemoryStorage extends RoundsDataStorage {

  private var dkgR1Data = Seq[R1Data]()
  private var dkgR2Data = Seq[R2Data]()
  private var dkgR3Data = Seq[R3Data]()
  private var dkgR4Data = Seq[R4Data]()
  private var dkgR5_1Data = Seq[R5_1Data]()
  private var dkgR5_2Data = Seq[R5_2Data]()

  private var tallyR1Data = Seq[MultiDelegTallyR1Data]()
  private var tallyR2Data = Seq[MultiDelegTallyR2Data]()
  private var tallyR3Data = Seq[MultiDelegTallyR3Data]()
  private var tallyR4Data = Seq[MultiDelegTallyR4Data]()

  private var expertBallots = Seq[MultiDelegExpertBallot]()

  override def getDKGr1: Seq[R1Data] = dkgR1Data
  override def updateDKGr1(data: Seq[R1Data]): Try[Unit] = Try(dkgR1Data ++= data)

  override def getDKGr2: Seq[R2Data] = dkgR2Data
  override def updateDKGr2(data: Seq[R2Data]): Try[Unit] = Try(dkgR2Data ++= data)

  override def getDKGr3: Seq[R3Data] = dkgR3Data
  override def updateDKGr3(data: Seq[R3Data]): Try[Unit] = Try(dkgR3Data ++= data)

  override def getDKGr4: Seq[R4Data] = dkgR4Data
  override def updateDKGr4(data: Seq[R4Data]): Try[Unit] = Try(dkgR4Data ++= data)

  override def getDKGr5_1: Seq[R5_1Data] = dkgR5_1Data
  override def updateDKGr5_1(data: Seq[R5_1Data]): Try[Unit] = Try(dkgR5_1Data ++= data)

  override def getDKGr5_2: Seq[R5_2Data] = dkgR5_2Data
  override def updateDKGr5_2(data: Seq[R5_2Data]): Try[Unit] = Try(dkgR5_2Data ++= data)

  override def getVoterBallots: Seq[MultiDelegVoterBallot] = ???
  override def updateVotersBallots(data: Seq[MultiDelegVoterBallot]): Try[Unit] = ???

  override def getExpertBallots: Seq[MultiDelegExpertBallot] = expertBallots
  override def updateExpertBallots(data: Seq[MultiDelegExpertBallot]): Try[Unit] = Try(expertBallots ++= data)

  override def getTallyR1: Seq[MultiDelegTallyR1Data] = tallyR1Data
  override def updateTallyR1(data: Seq[MultiDelegTallyR1Data]): Try[Unit] = Try(tallyR1Data ++= data)

  override def getTallyR2: Seq[MultiDelegTallyR2Data] = tallyR2Data
  override def updateTallyR2(data: Seq[MultiDelegTallyR2Data]): Try[Unit] = Try(tallyR2Data ++= data)

  override def getTallyR3: Seq[MultiDelegTallyR3Data] = tallyR3Data
  override def updateTallyR3(data: Seq[MultiDelegTallyR3Data]): Try[Unit] = Try(tallyR3Data ++= data)

  override def getTallyR4: Seq[MultiDelegTallyR4Data] = tallyR4Data
  override def updateTallyR4(data: Seq[MultiDelegTallyR4Data]): Try[Unit] = Try(tallyR4Data ++= data)
}