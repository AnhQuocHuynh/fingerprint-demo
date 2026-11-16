package com.se405.securestudentvault;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES-256-GCM key lives in AndroidKeyStore and is non-exportable.
 * Biometrics do not encrypt anything: per-use authentication only lets
 * KeyMint inside the TEE run this cipher.
 */
public final class CryptoManager {

    public static final String KEY_ALIAS = "se405_student_vault_key";

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;

    private final KeyStore keyStore;

    public CryptoManager() throws GeneralSecurityException, IOException {
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
    }

    public boolean containsKey() {
        try {
            return keyStore.containsAlias(KEY_ALIAS);
        } catch (KeyStoreException exception) {
            return false;
        }
    }

    public Cipher getEncryptCipher() throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateSecretKey());
        return cipher;
    }

    public Cipher getDecryptCipher(byte[] iv) throws GeneralSecurityException {
        if (iv == null || iv.length == 0) {
            throw new java.security.InvalidAlgorithmParameterException("IV is empty");
        }
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.DECRYPT_MODE,
                requireExistingSecretKey(),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher;
    }

    public void deleteKey() throws GeneralSecurityException, IOException {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS);
        }
        keyStore.load(null);
    }

    private SecretKey getOrCreateSecretKey() throws GeneralSecurityException {
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            generateKey();
        }
        return requireExistingSecretKey();
    }

    private SecretKey requireExistingSecretKey() throws GeneralSecurityException {
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            throw new KeyStoreException("Missing AndroidKeyStore alias " + KEY_ALIAS);
        }
        Key key = keyStore.getKey(KEY_ALIAS, null);
        if (!(key instanceof SecretKey)) {
            throw new KeyStoreException("Alias " + KEY_ALIAS + " is not a SecretKey");
        }
        return (SecretKey) key;
    }

    @SuppressWarnings("deprecation")
    private void generateKey() throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(AES_KEY_BITS)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(-1);
        }
        keyGenerator.init(builder.build());
        keyGenerator.generateKey();
    }
}
