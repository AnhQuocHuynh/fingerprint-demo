package com.se405.securestudentvault;

import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import com.google.android.material.button.MaterialButton;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Locale;
import java.util.concurrent.Executor;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "SecureStudentVault";

    private enum PendingOp {
        NONE,
        ENCRYPT,
        DECRYPT
    }

    private EditText editPlaintext;
    private MaterialButton buttonEncrypt;
    private MaterialButton buttonDecrypt;
    private MaterialButton buttonReset;
    private TextView textEncryptStatus;
    private TextView textKeyAlias;
    private TextView textIv;
    private TextView textCiphertext;
    private LinearLayout resultPanel;
    private TextView resultTitle;
    private TextView resultBody;

    private VaultStorage vaultStorage;
    private CryptoManager cryptoManager;
    private BiometricPrompt biometricPrompt;

    private PendingOp pendingOp = PendingOp.NONE;
    private byte[] pendingPayload;
    private boolean authInProgress;
    private boolean suppressAuthUi;

    private final BiometricPrompt.AuthenticationCallback authenticationCallback =
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(
                        @NonNull BiometricPrompt.AuthenticationResult result) {
                    authInProgress = false;
                    setCryptoButtonsEnabled(true);
                    if (suppressAuthUi) {
                        suppressAuthUi = false;
                        clearPending();
                        return;
                    }
                    finishAuthorizedOperation(result);
                }

                @Override
                public void onAuthenticationFailed() {
                    if (suppressAuthUi) {
                        return;
                    }
                    showDenied(
                            R.string.result_denied,
                            getString(R.string.result_auth_failed_body),
                            false);
                }

                @Override
                public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                    authInProgress = false;
                    setCryptoButtonsEnabled(true);
                    if (suppressAuthUi) {
                        suppressAuthUi = false;
                        clearPending();
                        return;
                    }
                    clearPending();
                    showDenied(
                            R.string.result_denied,
                            getString(R.string.result_auth_error_body, errString),
                            false);
                }
            };

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        bindViews();
        vaultStorage = new VaultStorage(this);
        Executor executor = ContextCompat.getMainExecutor(this);
        biometricPrompt = new BiometricPrompt(this, executor, authenticationCallback);
        try {
            cryptoManager = new CryptoManager();
        } catch (GeneralSecurityException | IOException exception) {
            Log.e(TAG, "AndroidKeyStore unavailable", exception);
            cryptoManager = null;
            showWarning(R.string.result_keystore_title, exception.getMessage());
        }
        buttonEncrypt.setOnClickListener(v -> onEncryptClicked());
        buttonDecrypt.setOnClickListener(v -> onDecryptClicked());
        buttonReset.setOnClickListener(v -> onResetClicked());
        refreshInspector();
        if (cryptoManager != null) {
            showIdle();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshInspector();
    }

    private void bindViews() {
        editPlaintext = requireView(R.id.editPlaintext);
        buttonEncrypt = requireView(R.id.buttonEncrypt);
        buttonDecrypt = requireView(R.id.buttonDecrypt);
        buttonReset = requireView(R.id.buttonReset);
        textEncryptStatus = requireView(R.id.textEncryptStatus);
        textKeyAlias = requireView(R.id.textKeyAlias);
        textIv = requireView(R.id.textIv);
        textCiphertext = requireView(R.id.textCiphertext);
        resultPanel = requireView(R.id.resultPanel);
        resultTitle = requireView(R.id.resultTitle);
        resultBody = requireView(R.id.resultBody);
    }

    private void onEncryptClicked() {
        if (!prepareForPrompt()) {
            return;
        }
        String plaintext = editPlaintext.getText() == null
                ? ""
                : editPlaintext.getText().toString();
        if (plaintext.trim().isEmpty()) {
            textEncryptStatus.setText(R.string.status_need_plaintext);
            textEncryptStatus.setTextColor(color(R.color.denied_title));
            return;
        }
        if (!ensureBiometricReady()) {
            return;
        }
        try {
            Cipher cipher = cryptoManager.getEncryptCipher();
            pendingPayload = plaintext.getBytes(StandardCharsets.UTF_8);
            launchPrompt(cipher, PendingOp.ENCRYPT, encryptPrompt());
        } catch (GeneralSecurityException exception) {
            Log.e(TAG, "Encrypt cipher init failed", exception);
            clearPending();
            presentKeystoreException(exception);
        }
    }

    private void onDecryptClicked() {
        if (!prepareForPrompt()) {
            return;
        }
        if (!vaultStorage.hasRecord()) {
            showNeutral(R.string.result_no_ciphertext_title, getString(R.string.result_no_ciphertext_body));
            return;
        }
        byte[] iv = vaultStorage.getIvBytes();
        byte[] ciphertext = vaultStorage.getCiphertextBytes();
        if (iv == null || ciphertext == null) {
            showWarning(R.string.result_keystore_title, getString(R.string.result_bad_record));
            return;
        }
        if (!ensureBiometricReady()) {
            return;
        }
        try {
            Cipher cipher = cryptoManager.getDecryptCipher(iv);
            pendingPayload = ciphertext;
            launchPrompt(cipher, PendingOp.DECRYPT, decryptPrompt());
        } catch (GeneralSecurityException exception) {
            Log.e(TAG, "Decrypt cipher init failed", exception);
            clearPending();
            presentKeystoreException(exception);
        }
    }

    private void onResetClicked() {
        if (authInProgress && biometricPrompt != null) {
            suppressAuthUi = true;
            biometricPrompt.cancelAuthentication();
        }
        authInProgress = false;
        clearPending();
        setCryptoButtonsEnabled(true);
        if (cryptoManager == null) {
            showWarning(R.string.result_keystore_title, getString(R.string.status_reset_failed, "AndroidKeyStore"));
            refreshInspector();
            return;
        }
        try {
            cryptoManager.deleteKey();
            vaultStorage.clear();
            textEncryptStatus.setText(R.string.status_reset);
            textEncryptStatus.setTextColor(color(R.color.status_ok));
            showNeutral(R.string.status_setup_title, getString(R.string.status_reset));
        } catch (GeneralSecurityException | IOException exception) {
            Log.e(TAG, "Reset failed", exception);
            showWarning(
                    R.string.result_keystore_title,
                    getString(R.string.status_reset_failed, safeMessage(exception)));
        }
        refreshInspector();
    }

    private boolean prepareForPrompt() {
        if (authInProgress) {
            return false;
        }
        if (cryptoManager == null || biometricPrompt == null) {
            showWarning(R.string.result_keystore_title, getString(R.string.status_no_hardware));
            return false;
        }
        return true;
    }

    private boolean ensureBiometricReady() {
        BiometricManager manager = BiometricManager.from(this);
        int status = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        switch (status) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return true;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                showWarning(R.string.status_setup_title, getString(R.string.status_none_enrolled));
                return false;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                showWarning(R.string.status_setup_title, getString(R.string.status_no_hardware));
                return false;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                showWarning(R.string.status_setup_title, getString(R.string.status_hw_unavailable));
                return false;
            default:
                showWarning(
                        R.string.status_setup_title,
                        getString(R.string.status_biometric_unavailable, status));
                return false;
        }
    }

    private void launchPrompt(
            @NonNull Cipher cipher,
            @NonNull PendingOp operation,
            @NonNull BiometricPrompt.PromptInfo promptInfo) {
        pendingOp = operation;
        authInProgress = true;
        suppressAuthUi = false;
        setCryptoButtonsEnabled(false);
        try {
            biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
        } catch (RuntimeException exception) {
            Log.e(TAG, "BiometricPrompt.authenticate failed", exception);
            authInProgress = false;
            clearPending();
            setCryptoButtonsEnabled(true);
            showDenied(R.string.result_denied, safeMessage(exception), false);
        }
    }

    private void finishAuthorizedOperation(@NonNull BiometricPrompt.AuthenticationResult result) {
        BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
        Cipher cipher = cryptoObject == null ? null : cryptoObject.getCipher();
        if (cipher == null) {
            clearPending();
            showDenied(
                    R.string.result_denied,
                    getString(R.string.result_missing_crypto_object),
                    false);
            return;
        }
        try {
            if (pendingOp == PendingOp.ENCRYPT) {
                completeEncrypt(cipher);
            } else if (pendingOp == PendingOp.DECRYPT) {
                completeDecrypt(cipher);
            } else {
                showDenied(R.string.result_denied, getString(R.string.result_missing_crypto_object), false);
            }
        } catch (UserNotAuthenticatedException exception) {
            Log.e(TAG, "KeyMint rejected doFinal", exception);
            showDenied(
                    R.string.result_denied,
                    getString(R.string.result_user_not_authenticated),
                    false);
        } catch (BadPaddingException | IllegalBlockSizeException exception) {
            Log.e(TAG, "Cipher.doFinal rejected payload", exception);
            showDenied(
                    R.string.result_tag_mismatch_title,
                    getString(R.string.result_tag_mismatch_body),
                    false);
        } catch (GeneralSecurityException exception) {
            Log.e(TAG, "doFinal failed", exception);
            if (isPermanentlyInvalidated(exception)) {
                showInvalidated();
            } else {
                showDenied(R.string.result_denied, safeMessage(exception), false);
            }
        } finally {
            clearPending();
            refreshInspector();
        }
    }

    private void completeEncrypt(@NonNull Cipher cipher)
            throws GeneralSecurityException, BadPaddingException, IllegalBlockSizeException {
        if (pendingPayload == null) {
            showDenied(R.string.result_denied, getString(R.string.status_need_plaintext), false);
            return;
        }
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(pendingPayload);
        if (iv == null || iv.length == 0) {
            showWarning(R.string.result_keystore_title, getString(R.string.result_bad_record));
            return;
        }
        if (!vaultStorage.save(ciphertext, iv)) {
            showWarning(R.string.result_keystore_title, getString(R.string.result_bad_record));
            return;
        }
        textEncryptStatus.setText(R.string.status_encrypted);
        textEncryptStatus.setTextColor(color(R.color.status_ok));
        showNeutral(
                R.string.result_after_encrypt_title,
                getString(R.string.result_after_encrypt_body));
    }

    private void completeDecrypt(@NonNull Cipher cipher)
            throws GeneralSecurityException, BadPaddingException, IllegalBlockSizeException {
        if (pendingPayload == null) {
            showNeutral(
                    R.string.result_no_ciphertext_title,
                    getString(R.string.result_no_ciphertext_body));
            return;
        }
        byte[] plaintext = cipher.doFinal(pendingPayload);
        String text = new String(plaintext, StandardCharsets.UTF_8);
        showSuccess(text);
    }

    private void presentKeystoreException(@NonNull GeneralSecurityException exception) {
        if (isPermanentlyInvalidated(exception)) {
            showInvalidated();
            return;
        }
        String message = exception.getMessage();
        if (message != null) {
            String lower = message.toLowerCase(Locale.US);
            if (lower.contains("enrolled") || lower.contains("biometric")) {
                showWarning(R.string.status_setup_title, getString(R.string.status_none_enrolled));
                return;
            }
            if (lower.contains("missing androidkeystore alias")) {
                showWarning(R.string.result_keystore_title, getString(R.string.result_missing_key));
                return;
            }
        }
        showWarning(R.string.result_keystore_title, safeMessage(exception));
    }

    private boolean isPermanentlyInvalidated(@Nullable Throwable error) {
        Throwable current = error;
        int guard = 0;
        while (current != null && guard < 8) {
            if (current instanceof KeyPermanentlyInvalidatedException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null
                    && message.toLowerCase(Locale.US).contains("permanently invalidated")) {
                return true;
            }
            current = current.getCause();
            guard++;
        }
        return false;
    }

    @NonNull
    private BiometricPrompt.PromptInfo encryptPrompt() {
        return new BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.prompt_encrypt_title))
                .setSubtitle(getString(R.string.prompt_encrypt_subtitle))
                .setDescription(getString(R.string.prompt_encrypt_description))
                .setNegativeButtonText(getString(R.string.action_cancel))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setConfirmationRequired(false)
                .build();
    }

    @NonNull
    private BiometricPrompt.PromptInfo decryptPrompt() {
        return new BiometricPrompt.PromptInfo.Builder()
                .setTitle(getString(R.string.prompt_decrypt_title))
                .setSubtitle(getString(R.string.prompt_decrypt_subtitle))
                .setDescription(getString(R.string.prompt_decrypt_description))
                .setNegativeButtonText(getString(R.string.action_cancel))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setConfirmationRequired(false)
                .build();
    }

    private void refreshInspector() {
        boolean keyPresent = cryptoManager != null && cryptoManager.containsKey();
        textKeyAlias.setText(getString(
                keyPresent ? R.string.alias_present : R.string.alias_absent,
                CryptoManager.KEY_ALIAS));
        String iv = vaultStorage == null ? null : vaultStorage.getIvBase64();
        String ciphertext = vaultStorage == null ? null : vaultStorage.getCiphertextBase64();
        textIv.setText(iv == null ? getString(R.string.inspector_empty) : iv);
        textCiphertext.setText(ciphertext == null ? getString(R.string.inspector_empty) : ciphertext);
    }

    private void showSuccess(@NonNull String plaintext) {
        paintResult(
                R.color.success_bg,
                R.color.success_title,
                R.color.success_body,
                getString(R.string.result_success),
                plaintext,
                28f);
    }

    private void showDenied(@StringRes int titleRes, @NonNull String body, boolean largeBody) {
        paintResult(
                R.color.denied_bg,
                R.color.denied_title,
                R.color.denied_body,
                getString(titleRes),
                body,
                largeBody ? 28f : 16f);
    }

    private void showInvalidated() {
        paintResult(
                R.color.invalid_bg,
                R.color.invalid_title,
                R.color.invalid_body,
                getString(R.string.result_invalidated),
                getString(R.string.result_invalidated_detail),
                16f);
    }

    private void showIdle() {
        showNeutral(R.string.result_idle_title, getString(R.string.result_idle_body));
    }

    private void showNeutral(@StringRes int titleRes, @NonNull String body) {
        paintResult(
                R.color.neutral_bg,
                R.color.neutral_title,
                R.color.neutral_body,
                getString(titleRes),
                body,
                16f);
    }

    private void showWarning(@StringRes int titleRes, @Nullable String body) {
        paintResult(
                R.color.warn_bg,
                R.color.warn_title,
                R.color.warn_body,
                getString(titleRes),
                body == null || body.isEmpty() ? getString(R.string.status_hw_unavailable) : body,
                16f);
    }

    private void paintResult(
            int backgroundColor,
            int titleColor,
            int bodyColor,
            @NonNull String title,
            @NonNull String body,
            float bodySizeSp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color(backgroundColor));
        drawable.setCornerRadius(16f * getResources().getDisplayMetrics().density);
        resultPanel.setBackground(drawable);
        resultTitle.setTextColor(color(titleColor));
        resultBody.setTextColor(color(bodyColor));
        resultTitle.setText(title);
        resultBody.setText(body);
        resultBody.setTextSize(TypedValue.COMPLEX_UNIT_SP, bodySizeSp);
    }

    private void setCryptoButtonsEnabled(boolean enabled) {
        buttonEncrypt.setEnabled(enabled);
        buttonDecrypt.setEnabled(enabled);
    }

    private void clearPending() {
        pendingOp = PendingOp.NONE;
        pendingPayload = null;
    }

    private int color(int colorRes) {
        return ContextCompat.getColor(this, colorRes);
    }

    @NonNull
    private String safeMessage(@NonNull Exception exception) {
        String message = exception.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return exception.getClass().getSimpleName();
        }
        return message;
    }

    @NonNull
    private <T extends View> T requireView(int id) {
        T view = findViewById(id);
        if (view == null) {
            throw new IllegalStateException("Missing view id " + id);
        }
        return view;
    }
}
