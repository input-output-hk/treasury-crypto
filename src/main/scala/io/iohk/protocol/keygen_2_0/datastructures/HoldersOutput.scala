package io.iohk.protocol.keygen_2_0.datastructures

import io.iohk.protocol.keygen_2_0.rnce_encryption.basic.light.data.RncePublicKeyLight

case class OutputDKG(
                      sk1_shares:    Seq[SecretShare],   // shares of the first partial secret key
                      sk2_shares:    Seq[SecretShare],   // shares of the second partial secret key
                      pubKeyPartial: RncePublicKeyLight  // partial public key: g1^sk1 * g2^sk2
                    // proof: CorrectSharesEncryptionDkg
                    )

case class OutputMaintenance(
                              s1_shares: Seq[SecretShare],  // shares of the first secret share
                              s2_shares: Seq[SecretShare]   // shares of the second secret share
                              // proof: CorrectSharesEncryptionDkg
                            )

case class HoldersOutput(dkg:         Option[OutputDKG],
                         maintenance: Option[OutputMaintenance])
