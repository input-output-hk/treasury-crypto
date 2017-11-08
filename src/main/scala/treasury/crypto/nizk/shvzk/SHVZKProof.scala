package treasury.crypto.nizk.shvzk

import treasury.crypto.core._

class SHVZKProof(val IBA: Seq[(Point, Point, Point)],
                 val Dk: Seq[Ciphertext],
                 val zwv: Seq[(Element, Element, Element)],
                 val R: Element) {
  def size = {
    IBA.foldLeft(0) { (a,x) =>
      a + x._1.getEncoded(true).size + x._2.getEncoded(true).size + x._3.getEncoded(true).size
    } +
    Dk.foldLeft(0) { (a,x) =>
      a + x._1.getEncoded(true).size + x._2.getEncoded(true).size
    } +
    zwv.foldLeft(0) { (a,x) =>
      a + x._1.toByteArray.size + x._2.toByteArray.size + x._3.toByteArray.size
    } +
    R.toByteArray.size
  }
}
