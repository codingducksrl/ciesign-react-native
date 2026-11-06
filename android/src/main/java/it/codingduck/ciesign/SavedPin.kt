package it.codingduck.ciesign

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import expo.modules.kotlin.exception.CodedException
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The CIE PIN encrypted with an AES-GCM Keystore key, in StrongBox when the device has it and otherwise in the TEE. The key
 * encrypts and decrypts only right after a strong biometric matches one enrolled when it was made. The file is not backed up.
 */
internal class SavedPin(private val context: Context) {
  /** The encrypted PIN, the NIS of its card and the decrypt cipher that a biometric unlocks. */
  class Saved(val card: String, val pin: ByteArray, val cipher: Cipher)

  private val file = File(context.noBackupFilesDir, "ciesign-pin")
  private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

  val canSave get() = BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

  fun status() = when {
    saved() != null -> "saved"
    canSave -> "available"
    else -> "unavailable"
  }

  /** Null when nothing is saved, or when a biometric enrolled since then invalidated the key. */
  fun saved(): Saved? {
    val (card, iv, pin) = runCatching { file.readLines() }.getOrNull()?.takeIf { it.size == 3 } ?: return null
    val cipher = cipher(Cipher.DECRYPT_MODE, Base64.decode(iv, Base64.NO_WRAP)) ?: return null.also { delete() }
    return Saved(card, Base64.decode(pin, Base64.NO_WRAP), cipher)
  }

  /** Encrypt cipher that a biometric unlocks; makes the key first when there is no valid one. */
  fun encrypter(): Cipher {
    if (!canSave) throw unavailable()
    return cipher(Cipher.ENCRYPT_MODE) ?: generate().let { cipher(Cipher.ENCRYPT_MODE) } ?: throw unavailable()
  }

  /** Encrypts `pin` with an unlocked [encrypter]; [store] saves the result once the card accepts the PIN. */
  fun seal(cipher: Cipher, pin: String): String =
    try {
      val iv = cipher.iv
      "${encode(iv)}\n${encode(cipher.doFinal(pin.toByteArray()))}"
    } catch (e: Exception) {
      throw unavailable(e)
    }

  /** Replaces the saved PIN; `card` is the NIS of the card that accepted it. */
  fun store(card: String, sealed: String) = file.writeText("$card\n$sealed")

  fun delete() {
    file.delete()
  }

  private fun cipher(mode: Int, iv: ByteArray? = null): Cipher? {
    val key = keyStore.getKey(ALIAS, null) as? SecretKey ?: return null
    return try {
      Cipher.getInstance("AES/GCM/NoPadding").apply { if (iv == null) init(mode, key) else init(mode, key, GCMParameterSpec(128, iv)) }
    } catch (e: KeyPermanentlyInvalidatedException) {
      null
    }
  }

  private fun generate() {
    val strongBox = Build.VERSION.SDK_INT >= 28 && context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    try {
      val key = if (strongBox) runCatching { key(true) }.getOrElse { key(false) } else key(false)
      val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
      val hardware = if (Build.VERSION.SDK_INT >= 31) {
        info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE && info.securityLevel != KeyProperties.SECURITY_LEVEL_UNKNOWN
      } else {
        @Suppress("DEPRECATION") info.isInsideSecureHardware
      }
      check(hardware && info.isUserAuthenticationRequirementEnforcedBySecureHardware) { "The Keystore key is not in secure hardware" }
    } catch (e: Exception) {
      keyStore.deleteEntry(ALIAS)
      throw unavailable(e)
    }
  }

  private fun key(strongBox: Boolean): SecretKey {
    val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setKeySize(256)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
      .apply {
        if (Build.VERSION.SDK_INT >= 30) setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        else @Suppress("DEPRECATION") setUserAuthenticationValidityDurationSeconds(-1)
        if (strongBox && Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(true)
      }
      .build()
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
  }

  private companion object {
    const val ALIAS = "it.codingduck.ciesign.pin"

    fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    fun unavailable(cause: Throwable? = null) = CodedException("BIOMETRIC_UNAVAILABLE", "No strong biometric or secure hardware", cause)
  }
}
