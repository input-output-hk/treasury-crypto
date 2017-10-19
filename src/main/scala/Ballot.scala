import common.Ciphertext
import org.json.JSONObject

// The data structure for storing of the individual voter's/expert's choice
trait Ballot {
  final val VOTER_CHOISES_NUM = 3

  val issuerId: Int
  val proposalId: Int
  val unitVector: Array[Ciphertext]

  // Imports ballot from binary array (parses the binary data, sets the id of issuer, the number of experts and creates unitVector of necessary size and fills it)
  def importJSON(jsonBallot: JSONObject): Unit = ???

  // Imports ballot from JSON formatted data (parses the JSON format, sets the id of issuer, the number of experts and creates unitVector of necessary size and fills it)
  def importBin(binaryBallot: Array[Byte]): Unit = ???

  // Export of the ballot's internal state to JSON format for further transmission (useful for debugging)
  def exportJSON(): JSONObject = ???

  // Export of the ballot's internal state to binary format for further transmission (main method for exporting, as binary format is most compact)
  def exportBin(): Array[Byte] = ???
}

case class VoterBallot(override val issuerId: Int,
                       override val proposalId: Int,
                       val expertsNum: Int,
                       val stake: Array[Byte]) extends Ballot {
  // Unit vector of expertsNum + voterChoisesNum elements
  override val unitVector: Array[Ciphertext] = new Array(expertsNum + VOTER_CHOISES_NUM)

//  var unitNizks: Array[UnitNIZK] = null
//  var unitsSumNizk: UnitsSumNIZK = new UnitsSumNIZK
}

case class ExpertBallot(override val issuerId: Int,
                        override val proposalId: Int) extends Ballot {
  override val unitVector: Array[Ciphertext] = new Array(VOTER_CHOISES_NUM)
}