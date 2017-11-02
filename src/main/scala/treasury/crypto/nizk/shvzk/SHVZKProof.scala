package treasury.crypto.nizk.shvzk

import treasury.crypto.core._

class SHVZKProof(val IBA: Seq[(Point, Point, Point)],
                 val Dk: Seq[Ciphertext],
                 val zwv: Seq[(Element, Element, Element)],
                 val R: Element) {

}
