package io.iohk.protocol.voting_2_0.approval

import io.iohk.core.crypto.encryption.Randomness
import io.iohk.core.crypto.primitives.dlog.DiscreteLogGroup
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.RnceEncryptionLight
import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.{RnceCiphertextLight, RnceCrsLight, RncePublicKeyLight}

case class UnitVectorRnce(units: Seq[RnceCiphertextLight]){
  def +(that: UnitVectorRnce)
       (implicit group: DiscreteLogGroup): UnitVectorRnce = {
    require(units.length == that.units.length, "UVs are of different length")
    UnitVectorRnce(
      (units, that.units).zipped.map(_ + _)
    )
  }

  def *(scalars: Seq[Int])
       (implicit group: DiscreteLogGroup): UnitVectorRnce = {
    require(units.length == scalars.length, "Scalars length is inconsistent with UV length")
    UnitVectorRnce(
      (units, scalars).zipped.map(_ * _)
    )
  }
}
case class UnitVectorRandomness(r: Seq[Randomness])

object UnitVectorRnce {
  def buildEncryptedUv(non_zero_index: Int, uv_size: Int, pubKey: RncePublicKeyLight, crs: RnceCrsLight)
                      (implicit group: DiscreteLogGroup): (UnitVectorRnce, UnitVectorRandomness) = {
    val uv_r = (0 until uv_size).map{ index =>
      RnceEncryptionLight.encrypt(pubKey, BigInt(if(index == non_zero_index) 1 else 0), crs)
    }
    (UnitVectorRnce(uv_r.map(_._1)), UnitVectorRandomness(uv_r.map(_._2)))
  }

  def sum(uvs1: Seq[UnitVectorRnce],
          uvs2: Seq[UnitVectorRnce])
           (implicit group: DiscreteLogGroup): Seq[UnitVectorRnce] = {
    (uvs1, uvs2).zipped.map(_ + _)
  }
}