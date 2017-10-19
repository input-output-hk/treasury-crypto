import common.Ciphertext
import org.json.JSONObject

// The data structure for storing of the individual voter's/expert's choice
class Ballot {

  var issuerID = 0
  var proposalID = 0
  var expertsNum = 0
  val voterChoisesNum = 3

  // Unit vector of expertsNum + voterChoisesNum elements
  var unitVector: Array[Ciphertext] = null

//  var unitNizks: Array[UnitNIZK] = null
//  var unitsSumNizk: UnitsSumNIZK = new UnitsSumNIZK

  // Initializes ballot (sets the ID of issuer, the number of experts and creates the unitVector of necessary size)
  def initialize(_issuerID: Integer, _expertsNum: Integer, _proposalID: Integer): Unit = {
    issuerID = _issuerID
    expertsNum = _expertsNum
    proposalID = _proposalID
    unitVector = new Array[Ciphertext](expertsNum + voterChoisesNum)
  }

  // Imports ballot from binary array (parses the binary data, sets the id of issuer, the number of experts and creates unitVector of necessary size and fills it)
  def importJSON(jsonBallot: JSONObject): Unit = ???

  // Imports ballot from JSON formatted data (parses the JSON format, sets the id of issuer, the number of experts and creates unitVector of necessary size and fills it)
  def importBin(binaryBallot: Array[Byte]): Unit = ???

  // Export of the ballot's internal state to JSON format for further transmission (useful for debugging)
  def exportJSON(): JSONObject = ???

  // Export of the ballot's internal state to binary format for further transmission (main method for exporting, as binary format is most compact)
  def exportBin(): Array[Byte] = ???
}
