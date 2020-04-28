package io.iohk.protocol

import io.iohk.core.crypto.encryption.PubKey

/**
  * The Identifier deterministically assigns T values to public keys. Given the same set of keys, an identifier will
  * always assign the same values to keys.
  *
  * @param pubKeys
  * @tparam T
  */
abstract class Identifier[T](val pubKeys: Seq[PubKey]) {

  require(pubKeys.distinct.size == pubKeys.size, "All public keys should be distinct!")

  protected def sorter(key1: PubKey, key2: PubKey): Boolean = {
    (key1.compare(key2) >= 0)
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

class CommitteeIdentifier(pubKeys: Seq[PubKey]) extends ExpertIdentifier(pubKeys) {}

/**
  * SimpleIdentifier assigns ids to pub keys based on their index in the initial Seq
  *
  * @param pubKeys
  */
class SimpleIdentifier(pubKeys: Seq[PubKey]) extends Identifier[Int](pubKeys) {

  override def getId(pubKey: PubKey): Option[Int] = {
    val id = pubKeys.indexOf(pubKey)
    if (id >= 0) Some(id)
    else None
  }

  override def getPubKey(id: Int): Option[PubKey] = {
    if (id >= 0 && id < pubKeys.size)
      Some(pubKeys(id))
    else None
  }
}
