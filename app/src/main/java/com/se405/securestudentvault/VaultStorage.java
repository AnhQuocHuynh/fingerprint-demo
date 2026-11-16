package com.se405.securestudentvault;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * Disk only stores ciphertext and IV. The AES key stays in AndroidKeyStore.
 */
public final class VaultStorage {

    static final String PREFS_NAME = "se405_student_vault";

    private static final String KEY_CIPHERTEXT = "ciphertext";
    private static final String KEY_IV = "iv";

    private final SharedPreferences preferences;

    public VaultStorage(@NonNull Context context) {
        preferences = context.getApplicationContext()
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public boolean save(@NonNull byte[] ciphertext, @NonNull byte[] iv) {
        return preferences.edit()
                .putString(KEY_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                .commit();
    }

    public void clear() {
        preferences.edit().clear().commit();
    }

    public boolean hasRecord() {
        return getCiphertextBase64() != null && getIvBase64() != null;
    }

    @Nullable
    public String getCiphertextBase64() {
        return nonEmpty(preferences.getString(KEY_CIPHERTEXT, null));
    }

    @Nullable
    public String getIvBase64() {
        return nonEmpty(preferences.getString(KEY_IV, null));
    }

    @Nullable
    public byte[] getCiphertextBytes() {
        return decode(getCiphertextBase64());
    }

    @Nullable
    public byte[] getIvBytes() {
        return decode(getIvBase64());
    }

    @Nullable
    private String nonEmpty(@Nullable String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        return value;
    }

    @Nullable
    private byte[] decode(@Nullable String value) {
        if (value == null) {
            return null;
        }
        try {
            return Base64.decode(value, Base64.NO_WRAP);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
