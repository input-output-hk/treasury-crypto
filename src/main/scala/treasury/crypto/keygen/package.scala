package treasury.crypto

import treasury.crypto.core._
import treasury.crypto.nizk.ElgamalDecrNIZK.ElgamalDecrNIZKProof

package object keygen {

  //----------------------------------------------------------
  // Round 1 data structures
  //
  case class SecretShare (receiverID:  Integer,
                          S:           HybridCiphertext)

  case class OpenedShare (receiverID:  Integer,
                          S:           HybridPlaintext)

  case class R1Data (issuerID: Integer,            // ID of commitments and shares issuer
                     E:        Array[Array[Byte]], // CRS commitments for coefficients of the both polynomials (E = g * a_i + h * b_i; i = [0; t) )
                     S_a:      Array[SecretShare], // poly_a shares for each of k = n-1 committee members
                     S_b:      Array[SecretShare]) // poly_b shares for each of k = n-1 committee members

  //----------------------------------------------------------
  // Round 2 data structures
  //
  case class ShareProof (encryptedShare:  HybridCiphertext,
                         decryptedShare:  HybridPlaintext,
                         NIZKProof:       ElgamalDecrNIZKProof)

  case class ComplaintR2(violatorID:        Integer,
                         issuerPublicKey:   PubKey,
                         shareProof_a:      ShareProof,
                         shareProof_b:      ShareProof)

  case class R2Data (complaints: Array[ComplaintR2])

  //----------------------------------------------------------
  // Round 3 data structures
  //
  case class R3Data (issuerID:    Integer,
                     commitments: Array[Array[Byte]])

  //----------------------------------------------------------
  // Round 4 data structures
  //
  case class ComplaintR4(violatorID:  Integer,
                         share_a:     OpenedShare,
                         share_b:     OpenedShare)

  case class R4Data (issuerID:    Integer,
                     complaints:  Array[ComplaintR4])

  //----------------------------------------------------------
  // Round 5.1 data structures
  //
  case class R5_1Data (issuerID:        Integer,
                       violatorsShares: Array[(Integer, OpenedShare)]) // decrypted share from violator to issuer of this message

  //----------------------------------------------------------
  // Round 5.2 data structures
  //
  type SharedPublicKey = Array[Byte]

  case class SecretKey (ownerID: Integer, secretKey: Array[Byte])

  case class R5_2Data (sharedPublicKey:     SharedPublicKey,
                       violatorsSecretKeys: Array[SecretKey])
}
