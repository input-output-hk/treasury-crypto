package treasury.crypto.keygen.datastructures

import treasury.crypto.core.{HasSize, Point, PubKey}
import treasury.crypto.nizk.ElgamalDecrNIZK.ElgamalDecrNIZKProof

//----------------------------------------------------------
// Tally decryption data structures
//
case class C1Share(
    issuerID:           Integer,
    issuerPubKey:       PubKey,
    decryptedC1:        Seq[Point],
    decryptedC1Proofs:  Seq[ElgamalDecrNIZKProof]
  ) extends HasSize {

    def size: Int = {
      Integer.BYTES +
      issuerPubKey.getEncoded(true).size +
      decryptedC1.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.getEncoded(true).size} +
      decryptedC1Proofs.foldLeft(0) {(totalSize, currentElement) => totalSize + currentElement.size}
    }
  }
