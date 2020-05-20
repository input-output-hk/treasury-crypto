package io.iohk.protocol.keygen

import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroupFactory.AvailableGroups
import io.iohk.protocol.{CommitteeIdentifier, CryptoContext}
import org.scalatest.FunSuite

import scala.util.{Failure, Success, Try}

class DistrKeyGenCommitteeTest extends FunSuite with DistrKeyGenSetup {

  test("R1Data generation") {
    val committeeMembers = createCommitteeMembers()
    val r1DataAll = committeeMembers.map(m => m.generateR1Data().get)
    val dkgObserver = new DistrKeyGenState(ctx, cmIdentifier)

    r1DataAll.foreach { r1Data =>
      // general checks performed by all
      require(dkgObserver.verifyR1Data(r1Data).isSuccess)

      // personal checks of committee members
      committeeMembers.foreach { m =>
        Try(m.extractAndVerifyPersonalR1Shares(r1Data)) match {
          case Success(r) => require(r.isDefined) // all shares should be valid in this test
          case Failure(e) => {
            // we can have an exception only if we try to extract shares from our own r1Data
            require(r1Data.issuerID == m.myCommitteeId)
            require(e.getMessage.contains("Invalid r1Data"))
          }
        }
      }
    }
  }
}

trait DistrKeyGenSetup {

  val g = DiscreteLogGroupFactory.constructDlogGroup(AvailableGroups.BC_secp256r1).get
  val ctx = new CryptoContext(Some(g.createRandomGroupElement.get), Some(g))

  import ctx.group

  val committeeSize = 10

  // used to generate a shared secret
  val committeeKeys = for (i <- 0 until committeeSize) yield {
    val privKey = group.createRandomNumber
    (privKey -> group.groupGenerator.pow(privKey).get)
  }

  // used to communicate with other members and as a member identifier
  val committeeTransportKeys = for (i <- 0 until committeeSize) yield {
    val privKey = group.createRandomNumber
    (privKey -> group.groupGenerator.pow(privKey).get)
  }

  val cmIdentifier = new CommitteeIdentifier(committeeTransportKeys.map(_._2))

  def createCommitteeMembers(): Seq[DistrKeyGenCommittee] = {
    committeeKeys.zip(committeeTransportKeys).map { case (key, transportKey) =>
      new DistrKeyGenCommittee(ctx, key._1, transportKey, group.createRandomNumber.toByteArray, cmIdentifier)
    }
  }
}
