package io.iohk.protocol.voting_2_0.approval

import io.iohk.protocol.CryptoContext
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.RnceEncryptionLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceCrsLight, RnceSecretKeyLight}
import io.iohk.protocol.voting_2_0.approval.VoteOption.{Abstain, No, Yes}
import io.iohk.protocol.voting_2_0.approval.ballot.{ExpertBallot, ExpertVote, VoterBallot, VoterVote}
import org.scalatest.FunSuite

import scala.collection.mutable.ArrayBuffer

class TestBallotsTally extends FunSuite {
  private val crs = CryptoContext.generateRandomCRS
  private val context = new CryptoContext(Option(crs))
  private val dlogGroup = context.group

  private val rnce_crs = RnceCrsLight(g1 = dlogGroup.createRandomGroupElement.get, g2 = dlogGroup.createRandomGroupElement.get)

  import context.group

  def decryptUv(sk: RnceSecretKeyLight, uv: UnitVectorRnce, crs: RnceCrsLight): Seq[Int] = {
    uv.units.map(unit => RnceEncryptionLight.decrypt(sk, unit, crs).get.toInt)
  }

  def decryptUvs(sk: RnceSecretKeyLight, uvs: Seq[UnitVectorRnce], crs: RnceCrsLight): Seq[Seq[Int]] = {
    uvs.map(decryptUv(sk, _, crs))
  }

  test("VoterBallot"){
    val params = VotingParameters(context, 2, 4)
    val (sk, pk) = RnceEncryptionLight.keygen(rnce_crs)

    val ballot0 = VoterBallot.create(params, 0, Seq(VoterVote(Some(0), None), VoterVote(Some(1), None)), pk, rnce_crs)
    val ballot1 = VoterBallot.create(params, 1, Seq(VoterVote(Some(0), None), VoterVote(Some(1), None)), pk, rnce_crs)
    val ballot2 = VoterBallot.create(params, 2, Seq(VoterVote(None, Some(Yes)), VoterVote(None, Some(No))), pk, rnce_crs)
    val ballot3 = VoterBallot.create(params, 3, Seq(VoterVote(None, Some(Yes)), VoterVote(None, Some(No))), pk, rnce_crs)

    val ballots_sum = VoterBallot.sum(Seq(ballot0, ballot1, ballot2, ballot3))
//    println(decryptUv(sk, ballots_sum(0), rnce_crs))
//    println(decryptUv(sk, ballots_sum(1), rnce_crs))

    assert(decryptUv(sk, ballots_sum(0), rnce_crs) == Seq(2, 0, 0, 0, 0, 0, 2)) // project 1
    assert(decryptUv(sk, ballots_sum(1), rnce_crs) == Seq(0, 2, 0, 0, 0, 2, 0)) // project 2
  }

  test("ExpertBallot"){
    val params = VotingParameters(context, 2, 4)
    val (sk, pk) = RnceEncryptionLight.keygen(rnce_crs)

    val ballot0 = ExpertBallot.create(params, 0, Seq(ExpertVote(Yes), ExpertVote(No)), pk, rnce_crs)
    val ballot1 = ExpertBallot.create(params, 0, Seq(ExpertVote(Yes), ExpertVote(No)), pk, rnce_crs)
    val ballot2 = ExpertBallot.create(params, 0, Seq(ExpertVote(Yes), ExpertVote(Abstain)), pk, rnce_crs)
    val ballot3 = ExpertBallot.create(params, 0, Seq(ExpertVote(Yes), ExpertVote(Abstain)), pk, rnce_crs)

    val ballots_sum = ExpertBallot.sum(Seq(ballot0, ballot1, ballot2, ballot3))

//    println(decryptUv(sk, ballots_sum(0), rnce_crs))
//    println(decryptUv(sk, ballots_sum(1), rnce_crs))

    assert(decryptUv(sk, ballots_sum(0), rnce_crs) == Seq(0, 0, 4)) // project 1
    assert(decryptUv(sk, ballots_sum(1), rnce_crs) == Seq(2, 2, 0)) // project 2
  }

  test("Tally"){
    val params = VotingParameters(context, 2, 4)
    val (sk, pk) = RnceEncryptionLight.keygen(rnce_crs)

    val voterBallots = ArrayBuffer[VoterBallot]()

    voterBallots.append(VoterBallot.create(params, 0, Seq(VoterVote(Some(0), None), VoterVote(Some(1), None)), pk, rnce_crs))
    voterBallots.append(VoterBallot.create(params, 1, Seq(VoterVote(Some(0), None), VoterVote(Some(1), None)), pk, rnce_crs))
    voterBallots.append(VoterBallot.create(params, 2, Seq(VoterVote(None, Some(Yes)), VoterVote(None, Some(No))), pk, rnce_crs))
    voterBallots.append(VoterBallot.create(params, 3, Seq(VoterVote(None, Some(Yes)), VoterVote(None, Some(No))), pk, rnce_crs))

    val expertBallots = ArrayBuffer[ExpertBallot]()

    expertBallots.append(ExpertBallot.create(params, 0, Seq(ExpertVote(Yes), ExpertVote(No)), pk, rnce_crs))
    expertBallots.append(ExpertBallot.create(params, 1, Seq(ExpertVote(Yes), ExpertVote(No)), pk, rnce_crs))
    expertBallots.append(ExpertBallot.create(params, 2, Seq(ExpertVote(Yes), ExpertVote(Abstain)), pk, rnce_crs))
    expertBallots.append(ExpertBallot.create(params, 3, Seq(ExpertVote(Yes), ExpertVote(Abstain)), pk, rnce_crs))

    val phase1Results = Tally.phase1(voterBallots, params)
    val delegations = decryptUvs(sk, phase1Results.delegations_sum, rnce_crs)
    delegations.foreach(println(_))

    val phase2Results = Tally.phase2(expertBallots, delegations, phase1Results.votes_sum)
    val result = decryptUvs(sk, phase2Results.votes_total_sum, rnce_crs)
    result.foreach(println(_))
  }
}
