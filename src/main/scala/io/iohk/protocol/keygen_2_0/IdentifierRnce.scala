package io.iohk.protocol.keygen_2_0

import io.iohk.protocol.keygen_2_0.rnce_encryption.RncePubKey

/**
  * The Identifier deterministically assigns T values to public keys. Given the same set of keys, an identifier will
  * always assign the same values to keys.
  *
  * @param pubKeys
  * @tparam T
  */
abstract class IdentifierRnce[T](val pubKeys: Seq[RncePubKey]) {

  require(pubKeys.distinct.size == pubKeys.size, "All public keys should be distinct!")

  // sorting RncePubKeys by value of the very first public key
  protected def sorter(key1: RncePubKey, key2: RncePubKey): Boolean = {
    key1.firstPubKey.compare(key2.firstPubKey) >= 0
  }

  protected val sortedRncePubKeys: Seq[RncePubKey] = pubKeys.sortWith(sorter)

  def getId(pubKey: RncePubKey): Option[T]
  def getRncePubKey(id: T): Option[RncePubKey]
}

class ExpertIdentifierRnce(pubKeys: Seq[RncePubKey]) extends IdentifierRnce[Int](pubKeys) {
  private lazy val indexedKeys = sortedRncePubKeys.zipWithIndex
  private lazy val idsMap = indexedKeys.toMap
  private lazy val keysMap = indexedKeys.map(_.swap).toMap

  override def getId(pubKey: RncePubKey): Option[Int] = {
    idsMap.get(pubKey)
  }

  override def getRncePubKey(id: Int): Option[RncePubKey] = {
    keysMap.get(id)
  }
}

class CommitteeIdentifierRnce(pubKeys: Seq[RncePubKey]) extends ExpertIdentifierRnce(pubKeys) {}

/**
  * SimpleIdentifier assigns ids to pub keys based on their index in the initial Seq
  *
  * @param pubKeys
  */
class SimpleIdentifierRnce(pubKeys: Seq[RncePubKey]) extends IdentifierRnce[Int](pubKeys) {

  override def getId(pubKey: RncePubKey): Option[Int] = {
    val id = pubKeys.indexOf(pubKey)
    if (id >= 0) Some(id)
    else None
  }

  override def getRncePubKey(id: Int): Option[RncePubKey] = {
    if (id >= 0 && id < pubKeys.size)
      Some(pubKeys(id))
    else None
  }
}
