import scala.collection.mutable.ArrayBuffer
import signatures._

class Voter(val voterID: Integer, val expertsNum: Integer, val publicKey: PubKey) extends EllipticCurveCryptosystem{

  // Produces encrypted ballot with NIZKs for its contents.
  def produceVote(proposalID: Integer, choice: VoteCases.Value): Ballot = ???

  // Calculates the total result of voting (based on all existing ballots of voters and experts)
  // NOTE: The privateKey parameter is temporary for simplified testing. In full version the decrypted by each committee member C1 part of ElGamal ciphertext should be obtained and multiplicated to each other for decryption of the each element of the unit vector.
  def tallyVotes(ballotsList: ArrayBuffer[Ballot], privateKey: PrivKey): Array[Integer] = ???
}
