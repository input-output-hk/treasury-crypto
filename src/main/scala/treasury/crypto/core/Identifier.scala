package treasury.crypto.core

import java.math.BigInteger

abstract class Identifier[T](val pubKeys: Seq[PubKey]) {

  protected def sorter(key1: PubKey, key2: PubKey): Boolean = {
    val x1 = key1.getXCoord.toBigInteger
    val x2 = key2.getXCoord.toBigInteger
    x1.compareTo(x2) match {
      case 1 => true
      case -1 => false
      case 0 => {
        val y1 = key1.getYCoord.toBigInteger
        val y2 = key2.getYCoord.toBigInteger
        y1.compareTo(y2) match {
          case 1 => true
          case _ => false
        }
      }
    }
  }

  protected val sortedPubKeys = pubKeys.sortWith(sorter)

  def getId(pubKey: PubKey): Option[T]
  def getPubKey(id: T): Option[PubKey]
}

class ExpertIdentifier(pubKeys: Seq[PubKey]) extends Identifier[Int](pubKeys) {
  private lazy val indexedKeys = sortedPubKeys.zipWithIndex
  private lazy val idsMap = indexedKeys.toMap
  private lazy val keysMap = indexedKeys.map(_.swap).toMap

  override def getId(pubKey: PubKey): Option[Int] = {
    idsMap.get(pubKey)
  }

  override def getPubKey(id: Int): Option[PubKey] = {
    keysMap.get(id)
  }
}

class CommitteeIdentifier(pubKeys: Seq[PubKey]) extends Identifier[BigInteger](pubKeys) {
  private lazy val indexedKeys = sortedPubKeys.zipWithIndex
  private lazy val idsMap = indexedKeys.map(t => t._1 -> BigInteger.valueOf(t._2 + 1)).toMap
  private lazy val keysMap = indexedKeys.map(t => BigInteger.valueOf(t._2 + 1) -> t._1).toMap

  override def getId(pubKey: PubKey): Option[BigInteger] = {
    idsMap.get(pubKey)
  }

  override def getPubKey(id: BigInteger): Option[PubKey] = {
    keysMap.get(id)
  }
}
