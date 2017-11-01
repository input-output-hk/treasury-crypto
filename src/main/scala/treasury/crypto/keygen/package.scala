package treasury.crypto

package object keygen {

  //----------------------------------------------------------
  // Committee member attributes
  //
  case class CommitteeMemberAttr(id:        Integer,
                                 publicKey: PubKey)

  //----------------------------------------------------------
  // Round 1 data structures
  //
  case class SecretShare (receiverID:  Integer,
                          x:           Integer,
                          S:           Array[Byte])

  case class R1Data (issuerID: Integer,            // ID of commitments and shares issuer
                     E:        Array[Array[Byte]], // CSR commitments for coefficients of the both polynomials (E = g * a_i + h * b_i; i = [0; t) )
                     S_a:      Array[SecretShare], // poly_a shares for each of k = n-1 committee members
                     S_b:      Array[SecretShare]) // poly_b shares for each of k = n-1 committee members

  //----------------------------------------------------------
  // Round 2 data structures
  //
  case class ComplainR2 (violatorID: Integer) // { // NIZK  }

  case class R2Data (complains: Array[ComplainR2])

  //----------------------------------------------------------
  // Round 3 data structures
  //
  case class R3Data (issuerID:    Integer,
                     commitments: Array[Array[Byte]])

  //----------------------------------------------------------
  // Round 4 data structures
  //
  case class ComplainR4 (violatorID:  Integer,
                         share_a:     SecretShare,
                         share_b:     SecretShare)

  case class R4Data (issuerID:  Integer,
                     complains: Array[ComplainR4])

  //----------------------------------------------------------
  // Round 5.1 data structures
  //
  case class R5_1Data (issuerID:  Integer,
                       violatorsShares: Array[(Integer, SecretShare)]) // decrypted share from violator to issuer of this message

  //----------------------------------------------------------
  // Round 5.2 data structures
  //
  type SharedPublicKey = Array[Byte]

  case class SecretKey (ownerID: Integer, secretKey: Array[Byte])

  case class R5_2Data (sharedPublicKey:     SharedPublicKey,
                       violatorsSecretKeys: Array[SecretKey])
}
