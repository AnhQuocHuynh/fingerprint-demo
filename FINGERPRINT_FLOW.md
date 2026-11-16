# Luồng bảo mật vân tay: cơ chế, code và kịch bản test

Tài liệu kỹ thuật của **Secure Student Vault** (`com.se405.securestudentvault`). Phần giới thiệu seminar, mô hình Fogg `B = MAP`, và cách tạo emulator nằm ở [README.md](README.md). File này chỉ ba việc: cơ chế chạy trong code, lưu ý khi tự viết lại luồng, và kịch bản test đã đối chiếu trên emulator.

Mục tiêu cần giữ khi đọc từng dòng: vân tay không mã hóa. `AES-256-GCM` mã hóa. Vân tay chỉ để `TEE` / KeyMint cấp `HardwareAuthToken` cho đúng một `Cipher` đã `init` bằng khóa trong `AndroidKeyStore`.

---

## 1. Thư viện, API và chỗ dùng

| Kỹ thuật | Gói / API | Chỗ trong project | Việc nó làm |
| --- | --- | --- | --- |
| UI xác thực | `androidx.biometric:biometric:1.1.0` | `app/build.gradle` dòng 38; `MainActivity.java` dòng 115, 277 | `BiometricPrompt` + `CryptoObject`. Bản 1.1.0 có `setAllowedAuthenticators`. |
| Activity host | `androidx.appcompat:appcompat:1.7.0` | `MainActivity extends AppCompatActivity` | `BiometricPrompt(FragmentActivity, …)` cần lifecycle của `FragmentActivity`. `AppCompatActivity` là đủ. |
| Nút, card, theme | `com.google.android.material:material:1.12.0` | `activity_main.xml`, `themes.xml` | Chỉ lớp hiển thị. Không tham gia mật mã. |
| Kho khóa | `java.security.KeyStore` provider `"AndroidKeyStore"` | `CryptoManager.java` dòng 27, 35–36 | Load keystore hệ thống. `load(null)` vì provider này không dùng password file. |
| Tạo khóa | `javax.crypto.KeyGenerator` + `KeyGenParameterSpec` | `CryptoManager.java` dòng 91–109 | Sinh AES bên trong KeyMint. App không nhận raw key bytes. |
| Chính sách auth | `KeyProperties`, `Build.VERSION_CODES.R` | `CryptoManager.java` dòng 101–107 | Bắt buộc xác thực mỗi lần dùng, chỉ `BIOMETRIC_STRONG` trên API 30+. |
| Phép toán | `javax.crypto.Cipher`, transformation `AES/GCM/NoPadding` | `CryptoManager.java` dòng 28, 47–62; `MainActivity.java` dòng 338, 362 | `init` trước prompt. `doFinal` chỉ sau khi callback trả lại đúng `Cipher`. |
| IV + tag GCM | `javax.crypto.spec.GCMParameterSpec(128, iv)` | `CryptoManager.java` dòng 30, 58–61 | Tag 128 bit. IV do Keystore sinh khi encrypt, app chỉ mang sang decrypt. |
| Hết hiệu lực khóa | `android.security.keystore.KeyPermanentlyInvalidatedException` | `MainActivity.java` dòng 387–402, 367–369 | Bắt ở `Cipher.init`, trước dialog. |
| Token bị từ chối | `android.security.keystore.UserNotAuthenticatedException` | `MainActivity.java` dòng 306–311 | `doFinal` không có `HardwareAuthToken`. |
| Kiểm tra cảm biến | `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)` | `MainActivity.java` dòng 245–265 | Chặn tạo khóa khi máy chưa có vân tay Class 3. |
| Bản mã trên đĩa | `SharedPreferences` + `android.util.Base64.NO_WRAP` | `VaultStorage.java` dòng 15–31 | Chỉ `ciphertext` và `iv`. |
| Quyền | `android.permission.USE_BIOMETRIC` | `AndroidManifest.xml` dòng 4 | Normal permission, không hiện hộp xin quyền. |
| Cảm biến không bắt buộc để cài | `android.hardware.fingerprint` `required=false` | `AndroidManifest.xml` dòng 6–8 | Máy không có vân tay vẫn cài được. App báo `CHƯA SẴN SÀNG` thay vì bị chặn cài. |
| Chống backup bản mã | `allowBackup=false`, `backup_rules.xml`, `data_extraction_rules.xml` | `AndroidManifest.xml` dòng 11–13 | File prefs `se405_student_vault.xml` không đi vào cloud backup hay device transfer. |
| Chống tapjacking trên nút mật mã | `android:filterTouchesWhenObscured="true"` | `activity_main.xml` dòng 104 và 248 | Nút Encrypt / Decrypt không nhận chạm khi một cửa sổ khác che. |

`minSdk` 24 (`app/build.gradle` dòng 11) vì `setInvalidatedByBiometricEnrollment` có từ API 24. `compileSdk` / `targetSdk` 35. Máy demo nên API 30+ để đi nhánh `setUserAuthenticationParameters`. Đã chạy thật trên emulator API 37.

---

## 2. Cơ chế hoạt động, bám từng dòng

### 2.1 Ba lớp không được trộn

```
[App process]                         [TEE / KeyMint]
EditText plaintext (RAM)              AES key blob, không export
BiometricPrompt.CryptoObject   --->   HardwareAuthToken gắn vào Cipher op
VaultStorage: Base64(IV), Base64(ct)  authenticator id lúc tạo khóa
```

- Plaintext chỉ sống trong `pendingPayload` (`MainActivity.java` dòng 61, 169, 197) cho đến `doFinal`.
- Khóa chỉ là handle `SecretKey` lấy bằng `keyStore.getKey` (`CryptoManager.java` dòng 83–87).
- Đĩa chỉ có hai chuỗi Base64 (`VaultStorage.java` dòng 27–30).

### 2.2 Tạo khóa, lần encrypt đầu

`getEncryptCipher` (`CryptoManager.java` dòng 47–50) gọi `getOrCreateSecretKey`. Alias chưa có thì `generateKey` (dòng 72–77, 91–109):

```91:110:app/src/main/java/com/se405/securestudentvault/CryptoManager.java
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
```

Ý nghĩa từng cờ:

| Cờ | Giá trị trong app | Hệ quả |
| --- | --- | --- |
| Algorithm / block / padding | AES, GCM, NoPadding | Khớp chuỗi `AES/GCM/NoPadding` ở dòng 28. Lệch một trong hai chỗ thì `Cipher.init` thất bại. |
| `setKeySize(256)` | 256 bit | Đủ để gọi là AES-256. |
| `setUserAuthenticationRequired(true)` | bắt buộc | KeyMint từ chối operation khi không có xác thực. `setInvalidatedByBiometricEnrollment` chỉ có hiệu lực khi cờ này bật. |
| `setInvalidatedByBiometricEnrollment(true)` | bật | Thêm hoặc xóa hết vân tay làm đổi authenticator id. Key blob cũ không mở được nữa. |
| API ≥ 30: `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` | timeout 0 | Mỗi `doFinal` cần một lần xác thực mới. Chỉ sinh trắc Class 3 (strong) ký được token. PIN không ký được token cho khóa này. |
| API 24–29: `setUserAuthenticationValidityDurationSeconds(-1)` | -1 | Cùng nghĩa “mỗi lần dùng” trên API cũ. Hàm này deprecated từ API 30 nên method có `@SuppressWarnings("deprecation")`. Hai API không được gọi cùng một lần. |

`Cipher.init(ENCRYPT_MODE, secretKey)` ở dòng 49 thành công mà chưa cần vân tay. Với khóa per-use, `init` chỉ mở operation. KeyMint giữ operation ở trạng thái chờ token. Token được gắn khi `BiometricPrompt` xác thực `CryptoObject`.

Decrypt không gọi `generateKey`. `getDecryptCipher` dùng `requireExistingSecretKey` (`CryptoManager.java` dòng 53–62 và 79–87). Alias mất thì ném `KeyStoreException`, không âm thầm tạo khóa mới. Khóa mới không giải được ciphertext cũ.

### 2.3 Chiều A — Encrypt

```
onEncryptClicked                         MainActivity.java:152
  ensureBiometricReady                   :164 và :245  BIOMETRIC_STRONG
  getEncryptCipher                       CryptoManager.java:47
        generateKey nếu alias trống      :72, :91
        Cipher.init(ENCRYPT_MODE)        :49
  pendingPayload = UTF-8                 MainActivity.java:169
  launchPrompt                           :170, :268
        authenticate(prompt, CryptoObject)  :277
  onAuthenticationSucceeded              :68
        finishAuthorizedOperation        :77, :287
        cipher = result.getCryptoObject().getCipher()  :288
        completeEncrypt                  :300, :331
              iv = cipher.getIV()        :337
              ciphertext = cipher.doFinal(pendingPayload)  :338
              VaultStorage.save          :343 → VaultStorage.java:27
```

`PromptInfo` encrypt (`MainActivity.java` dòng 406–414):

- `setAllowedAuthenticators(BIOMETRIC_STRONG)` cùng loại authenticator với khóa.
- `setNegativeButtonText("Hủy")`. Với androidx biometric 1.1.0, authenticator không gồm `DEVICE_CREDENTIAL` thì negative text là bắt buộc. Có `DEVICE_CREDENTIAL` thì không được đặt negative text, và `CryptoObject` cũng không dùng được với credential.
- `setConfirmationRequired(false)` vì vân tay không cần nút xác nhận thêm sau khi cảm biến khớp.

Sau `doFinal`, UI encrypt không hiện plaintext. `showNeutral` (dòng 349–351) báo bản mã đã lưu. Inspector đọc lại Base64 (`refreshInspector`, dòng 429–437).

### 2.4 Chiều B — Decrypt

```
onDecryptClicked                         MainActivity.java:178
  snapshot IV + ciphertext từ prefs      :186–197
  getDecryptCipher(iv)                   CryptoManager.java:53
        Cipher.init(DECRYPT_MODE, key, GCMParameterSpec(128, iv))  :58
        KeyPermanentlyInvalidatedException dừng tại đây
  launchPrompt DECRYPT                   MainActivity.java:198
  onAuthenticationSucceeded
        completeDecrypt                  :354
              plain = cipher.doFinal(pendingPayload)  :362
              UTF-8 → showSuccess        :363–364  nền success_bg
```

Snapshot byte trước prompt là có chủ đích. `Cipher` đã `init` với đúng IV đó. `doFinal` phải nhận ciphertext cùng bản ghi, không đọc lại prefs sau khi người dùng đã chạm.

`onAuthenticationFailed` (dòng 81–88) là vân tay đọc được nhưng không khớp. Prompt **không** đóng. App chỉ đổi khung thành `ACCESS DENIED` với `result_auth_failed_body`. Không gọi `doFinal`.

`onAuthenticationError` (dòng 92–104) là Hủy, user cancel, lockout, hoặc framework hủy prompt. Prompt đóng. Cũng `ACCESS DENIED`, body là `result_auth_error_body` kèm chuỗi hệ thống. `clearPending` để lần sau không giải nhầm buffer cũ.

### 2.5 Vì sao phải là `CryptoObject`

`authenticate` nhận hai tham số (`MainActivity.java` dòng 277):

```java
biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
```

Callback không có nhánh `if (success)`. Nó lấy cipher từ kết quả (dòng 287–297). `doFinal` nằm trong `completeEncrypt` / `completeDecrypt`, và hai method đó chỉ được gọi từ `finishAuthorizedOperation`, tức là chỉ từ `onAuthenticationSucceeded`.

Cổng thật là KeyMint. `CryptoObject` bảo framework gắn `HardwareAuthToken` vào **đúng** operation đã `init`. `doFinal` gửi operation đó sang TEE. Không có token, KeyMint ném `UserNotAuthenticatedException` (bắt ở dòng 306–311). Gọi callback Java giả không tạo token trong TEE, và không ủy quyền cho một `Cipher` khác.

Biến boolean trong process làm được việc ngược lại: dialog vẫn hiện, nhưng `doFinal` chạy khi attacker sửa biến hoặc nhảy cóc vào nhánh thành công. Demo này không có biến đó.

Giới hạn của thiết kế: `CryptoObject` không bảo vệ plaintext đã nằm trong RAM sau khi giải mã thành công, không chống TEE đã vỡ, và không chống người dùng bị lừa chạm đúng vân tay của mình. `filterTouchesWhenObscured` chỉ giảm tapjacking trên hai nút.

### 2.6 Khóa tự hủy khi đổi vân tay

Exception nổ ở `Cipher.init`, không phải trong callback vân tay.

Trên emulator API 37, log đúng là:

```
android.security.keystore.KeyPermanentlyInvalidatedException: Key permanently invalidated
    at CryptoManager.getDecryptCipher(CryptoManager.java:58)
    at MainActivity.onDecryptClicked(MainActivity.java:196)
```

`onDecryptClicked` bắt `GeneralSecurityException` (dòng 199–202) rồi `presentKeystoreException` (dòng 367). `isPermanentlyInvalidated` (dòng 387–402) xét cả exception bọc bên trong, vì một số bản Android bọc `KeyPermanentlyInvalidatedException` trong `InvalidKeyException` / `UnrecoverableKeyException`, hoặc chỉ để chuỗi `permanently invalidated` ở `getMessage()`.

UI đi `showInvalidated` (dòng 460): nền `invalid_bg` (`#7F1D1D`), chữ trắng, nguyên câu trong `strings.xml` tên `result_invalidated`. Focus vẫn là `MainActivity`. Không có cửa sổ `BiometricPrompt`.

Alias vẫn `containsAlias == true` (`CryptoManager.containsKey`, dòng 39–45). Invalidate không xóa tên khóa. Inspector vẫn ghi **CÓ MẶT**. Ciphertext trên đĩa cũng còn. Cả vân tay cũ và vân tay mới đều không dùng được blob cũ.

`deleteKey` (dòng 65–69) mới `deleteEntry` rồi `load(null)` lại. Nút Reset gọi `deleteKey` và `vaultStorage.clear` cùng lúc (`MainActivity.java` dòng 220–221). Xóa một trong hai sẽ để lại trạng thái không giải được hoặc khóa mồ côi.

### 2.7 Những gì có trên đĩa

`VaultStorage.PREFS_NAME = "se405_student_vault"` (dòng 15). File thật là `shared_prefs/se405_student_vault.xml`. `save` dùng `commit()` để ghi đồng bộ trước khi inspector đọc lại.

Bản ghi đã thấy trên emulator:

```xml
<map>
    <string name="ciphertext">KGPSB25T6gl3O6f27k8jaKDSmRX/D8HaSRq+VQ==</string>
    <string name="iv">UPXMRh+eu7Tjpg06</string>
</map>
```

`HELLO MOBILE` không xuất hiện trong file này. IV Base64 trên ngắn vì GCM IV của AndroidKeyStore là 12 byte. Ciphertext dài hơn plaintext vì kèm tag 128 bit.

---

## 3. Lưu ý khi tự implement lại

Những điểm dưới đây là chỗ dễ viết nhầm và vẫn “thấy dialog vân tay chạy”.

1. **`init` trước, `doFinal` sau, và chỉ trên cipher của `AuthenticationResult`.** Giữ cipher tự tạo rồi `doFinal` trong callback là cipher chưa được gắn token. Dùng `result.getCryptoObject().getCipher()`. Null thì dừng (`MainActivity.java` dòng 288–297).

2. **Timeout 0 và timeout dương là hai chế độ khác nhau.** `0` (hoặc `-1` ở API cũ) là mỗi lần dùng. Một số giây dương nghĩa là sau khi mở khóa máy, `doFinal` chạy trong khoảng đó mà không cần `CryptoObject`. Demo seminar cần chế độ từng lần, nên có hai lần chạm: một lúc mã hóa, một lúc giải mã.

3. **Không gọi cả `setUserAuthenticationParameters` lẫn `setUserAuthenticationValidityDurationSeconds`.** API 30+ chỉ nhánh `if` đầu. Nhánh `else` chỉ để máy API 24–29 còn biên dịch và chạy.

4. **`AUTH_BIOMETRIC_STRONG` ở khóa và ở `PromptInfo` phải cùng loại.** `BiometricManager.Authenticators.BIOMETRIC_STRONG` là Class 3. Face unlock Class 2 trên một số máy thật sẽ `canAuthenticate` thất bại hoặc không ký được token. Vân tay emulator là strong (dumpsys báo `oemStrength: 15`).

5. **Đừng thêm `DEVICE_CREDENTIAL` cho khóa gắn `CryptoObject`.** PIN dùng để *đăng ký* vân tay trong Settings. PIN không giải vault. Trộn credential vào `allowedAuthenticators` làm `PromptInfo.Builder.build()` ném `IllegalArgumentException` nếu còn negative button, và KeyMint cũng không nhận credential cho khóa strong-only.

6. **Tạo khóa khi chưa enroll vân tay sẽ ném `InvalidAlgorithmParameterException`.** Message hệ thống thường chứa `enrolled` / `biometric`. `ensureBiometricReady` (dòng 245) chặn sớm với câu tiếng Việt. `presentKeystoreException` (dòng 375) vẫn map message đó phòng khi keygen bị gọi trực tiếp.

7. **Đừng `generateKey` lại khi bắt `KeyPermanentlyInvalidatedException`.** Alias còn sống nên `containsAlias` vẫn true, `getOrCreateSecretKey` không tạo khóa mới. Nếu ai đó xóa alias rồi tạo khóa mới mà không xóa ciphertext, GCM sẽ `BadPaddingException` / `AEADBadTagException` ở `doFinal` (bắt ở dòng 312–317, title `BẢN MÃ KHÔNG HỢP LỆ`). Đó là lỗi toàn vẹn, không phải `ACCESS DENIED`.

8. **Thứ tự Test Case 3 là một phần của cơ chế.** Khóa phải được tạo *trước* khi thêm vân tay. Thêm vân tay rồi mới mã hóa thì khóa mới gắn authenticator id mới và sẽ không ném exception. Xóa sạch mọi vân tay cũng invalidate khóa, nhưng `canAuthenticate` trả `BIOMETRIC_ERROR_NONE_ENROLLED` trước `init`, nên UI có thể hiện “chưa đăng ký” thay vì câu cảnh báo đỏ đậm. Ca demo đúng là *thêm* một vân tay trong khi vẫn còn vân tay cũ.

9. **`KeyPermanentlyInvalidatedException` thường không đứng một mình.** Unwrap `getCause()` và tìm cả chuỗi `permanently invalidated`. Giới hạn độ sâu (trong code là 8) để khỏi vòng lặp cause tự trỏ.

10. **IV do Keystore sinh.** Không gọi `new IvParameterSpec` lúc encrypt, không set IV cố định. Lưu `cipher.getIV()` sau `init` (vẫn còn sau `doFinal`). Decrypt đưa lại nguyên IV đó vào `GCMParameterSpec`. Tái sử dụng IV cho cùng khóa là gãy an toàn GCM.

11. **`Cipher.getInstance("AES/GCM/NoPadding")` không chỉ provider.** `init` với `SecretKey` của AndroidKeyStore sẽ chuyển operation sang Keystore. Chỉ định provider `"AndroidKeyStore"` ngay từ `getInstance` cũng được, nhưng phải thống nhất. Transformation và `KeyGenParameterSpec` phải cùng GCM / NoPadding.

12. **`Base64.NO_WRAP` cả encode và decode.** `Base64.DEFAULT` chèn xuống dòng. Inspector và prefs sẽ lệch nhau nếu hai chiều dùng flag khác nhau. `VaultStorage.decode` nuốt `IllegalArgumentException` và trả null để prefs hỏng không làm crash UI.

13. **`getKey(alias, null)` cho secret key auth-bound.** `getEntry` trên một số API đòi khôi phục key và ném sớm hơn, trước khi `Cipher` kịp đưa vào `CryptoObject`. Google sample dùng `getKey`.

14. **Một `BiometricPrompt` cho cả vòng đời Activity** (`onCreate`, dòng 115), executor là main (`ContextCompat.getMainExecutor`). Tạo prompt mới mỗi lần bấm dễ mất callback khi framework còn giữ session cũ. `authInProgress` chặn bấm chồng. Reset trong lúc prompt đang mở phải `cancelAuthentication` và `suppressAuthUi` (dòng 206–212), nếu không callback Hủy sẽ đè câu “đã reset” bằng `ACCESS DENIED`.

15. **`onAuthenticationFailed` không được `clearPending`.** Người dùng còn được thử lại trên cùng prompt, cùng ciphertext đã snapshot. `onAuthenticationError` mới xóa pending.

16. **Đừng hạ `minSdk` dưới 24** nếu vẫn gọi `setInvalidatedByBiometricEnrollment` không bọc `SDK_INT`. Lint `NewApi` sẽ đỏ, và máy cũ không có method.

17. **`commit()` thay `apply()` cho bản mã demo.** `apply()` cập nhật cache trong process ngay, nhưng crash sát nút có thể mất lần ghi. Bản ghi này nhỏ, `commit()` chấp nhận được.

18. **Không log plaintext, key, hay ciphertext.** `Log.e` trong project chỉ ghi loại lỗi và stack. Inspector cố ý hiện Base64 vì đó là nội dung bài demo, không phải log.

19. **Xoay màn hình giữa chừng prompt làm mất `pendingPayload` và cipher.** `BiometricPrompt` sống theo lifecycle, nhưng field của Activity mới không còn buffer. Demo một màn hình nên tránh xoay lúc dialog đang mở. Không khóa orientation trong code để máy chiếu ngang vẫn dùng được.

20. **Emulator: `adb -e emu finger touch N` là finger id `N`, không phải “lần chạm thứ N”.** Chỉ enroll id `1` thì `touch 1` khớp, `touch 2` bị reject. Enroll thêm bằng `touch 2` thì id 2 trở thành vân tay hợp lệ *và* làm khóa cũ invalid. Đừng dùng `touch 2` cho cả hai vai trong cùng một buổi nếu chưa reset khóa.

21. **API 37 có thêm `adb shell cmd fingerprint fingerdown`.** Lệnh `adb emu finger touch` vẫn là lệnh làm enrollment và auth thành công trên bản emulator đã test. `fingerdown` không thay cho enroll.

22. **Backup.** `allowBackup="false"` một mình chưa kể hết trên API 31+. Cần `dataExtractionRules` và `fullBackupContent` loại đúng tên file `se405_student_vault.xml` (tên prefs cộng `.xml`).

---

## 4. Kịch bản test

### 4.1 Điều kiện

- Một emulator API 30+ (đã chạy API 37, `emulator-5554`). Có PIN màn hình. Chỉ enroll finger id `1`.
- App debug đã cài. Ô nhập là `HELLO MOBILE` hoặc một câu tự gõ để chứng minh không hard-code kết quả.
- Logcat lọc `SecureStudentVault`. Đếm HAL khi cần:

```bat
adb -e shell dumpsys fingerprint
```

Trường quan sát: `acceptCrypto`, `rejectCrypto`. Crypto-auth thành công tăng `acceptCrypto`. Vân tay lạ tăng `rejectCrypto` và **không** tăng `acceptCrypto`.

Lệnh cảm biến:

```bat
adb -e emu finger touch 1
adb -e emu finger touch 2
```

### 4.2 Test Case 1 — Happy path

| Bước | Thao tác | Code phải đi qua | Kỳ vọng trên máy |
| --- | --- | --- | --- |
| 1 | Bấm **Mã hóa & Lưu** | `onEncryptClicked` → `getEncryptCipher` → `generateKey` (lần đầu) → `Cipher.init` ENCRYPT | Dialog title mã hóa. Chưa có `doFinal`. |
| 2 | `finger touch 1` | `onAuthenticationSucceeded` → `completeEncrypt` dòng 338 → `VaultStorage.save` | Dialog đóng. Alias **CÓ MẶT**. IV và ciphertext Base64. Khung kết quả trung tính, không hiện plaintext. `acceptCrypto` +1. |
| 3 | Bấm **Mở ghi chú** | `onDecryptClicked` → `getDecryptCipher` → `init` DECRYPT | Dialog thứ hai. Khóa per-use nên lần chạm lúc mã hóa không còn giá trị. |
| 4 | `finger touch 1` | `completeDecrypt` dòng 362 → `showSuccess` | Nền xanh nhạt, **XÁC THỰC THÀNH CÔNG**, dòng dưới đúng plaintext. Ciphertext trong inspector không đổi. |

Đã thấy trên API 37: IV `UPXMRh+eu7Tjpg06`, ciphertext `KGPSB25T6gl3O6f27k8jaKDSmRX/D8HaSRq+VQ==`, body `HELLO MOBILE`. Prefs không chứa chuỗi plaintext.

### 4.3 Test Case 2 — Vân tay sai và Hủy

Làm khi finger id `2` **chưa** enroll. Nếu đã enroll id 2 cho Test Case 3 thì `touch 2` sẽ khớp và ca này không còn nghĩa.

| Bước | Thao tác | Callback | Kỳ vọng |
| --- | --- | --- | --- |
| 1 | Bấm Decrypt | `launchPrompt` | Dialog mở. |
| 2 | `finger touch 2` | `onAuthenticationFailed` dòng 81 | Prompt **còn**. `rejectCrypto` +1. `acceptCrypto` không tăng. Không có `doFinal`. Khung sau dialog là `ACCESS DENIED` + `result_auth_failed_body`. Inspector giữ nguyên. |
| 3 | Bấm **Hủy** | `onAuthenticationError` dòng 92 | Prompt đóng. Vẫn **ACCESS DENIED**, body `Xác thực dừng: …`. Nền đỏ nhạt `#FFEBEE`, chữ `#B71C1C`. |
| 4 | Decrypt lại + `touch 1` | `completeDecrypt` | Vẫn ra plaintext. Lần từ chối không xóa prefs. |

Ca Hủy đã chụp trên emulator: title `ACCESS DENIED`, body `Xác thực dừng: Hủy`, ciphertext còn nguyên. `rejectCrypto` đã lên 1 trong lúc dialog còn mở, trước khi bấm Hủy.

### 4.4 Test Case 3 — Thêm vân tay, khóa tự hủy

Chỉ làm sau Test Case 1, khi alias đã tồn tại.

| Bước | Thao tác | Code | Kỳ vọng |
| --- | --- | --- | --- |
| 1 | Settings, thêm vân tay. Lúc wizard bảo chạm cảm biến: `finger touch 2` vài lần đến khi báo Fingerprint added. | Không có code app. KeyMint đổi authenticator id. | App có thể bị đưa ra nền. |
| 2 | Quay lại app, nhìn inspector | `onResume` → `refreshInspector` | Ciphertext còn. Alias vẫn **CÓ MẶT**. |
| 3 | Bấm Decrypt | `getDecryptCipher` dòng 58 ném `KeyPermanentlyInvalidatedException` → `presentKeystoreException` → `showInvalidated` | Không có `BiometricPrompt`. Nền đỏ đậm, chữ trắng, đúng câu cảnh báo. Logcat có exception tại dòng 58. |
| 4 | `touch 1` hoặc `touch 2` | Không được gọi, vì prompt không mở | Không cứu được bản mã cũ. |
| 5 | Bấm Encrypt | `getEncryptCipher` cũng `init` trên cùng alias | Cùng cảnh báo. Không tạo khóa mới. |
| 6 | **Reset Key & Vault** | `deleteKey` + `clear` | Alias **KHÔNG CÓ MẶT**. IV và ciphertext `(trống)`. |
| 7 | Mã hóa lại bằng vân tay đang enroll | `generateKey` mới | Vault mới. Không giải ciphertext đã xóa. |

Đã thấy trên API 37 sau khi thêm finger id 2: `mCurrentFocus` vẫn là `MainActivity`, log `Key permanently invalidated`, khung đỏ đậm hiện đủ câu cảnh báo, ciphertext `KGPSB25T6gl3O6f27k8jaKDSmRX/D8HaSRq+VQ==` vẫn nằm trong inspector.

### 4.5 Ca phụ, không thay ba ca trên

| Tình huống | Điểm vào | UI |
| --- | --- | --- |
| Chưa enroll vân tay, bấm Encrypt | `ensureBiometricReady` → `BIOMETRIC_ERROR_NONE_ENROLLED` | Nền cam, `CHƯA SẴN SÀNG`, hướng dẫn Settings và lệnh `finger touch 1`. |
| Decrypt khi prefs trống | `onDecryptClicked` dòng 182 | Trung tính, `CHƯA CÓ BẢN MÃ`. Không mở prompt. |
| Plaintext toàn khoảng trắng | dòng 159 | Dòng trạng thái encrypt, không mở prompt. |
| Sửa prefs hoặc IV lệch khóa | `doFinal` → `BadPaddingException` dòng 312 | Nền đỏ nhạt, title **BẢN MÃ KHÔNG HỢP LỆ**, không phải `ACCESS DENIED`. |

### 4.6 Việc phải làm trước buổi demo kế tiếp

Emulator sau Test Case 3 đang có PIN (trong lần test này là `1111`) và **hai** vân tay. Khóa app đã chết. Trước khi diễn lại từ Test Case 1: bấm Reset trên app. Muốn Test Case 2 còn đúng, máy chỉ được còn finger id `1`. Vân tay id `2` đã enroll thì `touch 2` không còn là vân tay sai.
