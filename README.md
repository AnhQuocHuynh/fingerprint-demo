# Secure Student Vault

Demo kỹ thuật môn **SE405 – Mobile and Persuasive Computing**. Chủ đề: *Fingerprint Security – Từ cảm biến vật lý đến bảo vệ khóa mã hóa*.

Ứng dụng Android viết bằng **Java**. Mọi thao tác diễn ra on-device. Không có backend.

Namespace / `applicationId`: `com.se405.securestudentvault`.

---[FINGERPRINT_FLOW.md](FINGERPRINT_FLOW.md)

## 1. Giới thiệu dự án

### Bối cảnh

Seminar cần một bằng chứng chạy được, chiếu lên màn hình lớp, để tách hai khái niệm hay bị gộp làm một:

- **Sinh trắc học** là cơ chế xác thực cục bộ (người đang cầm máy có phải chủ thể đã đăng ký hay không).
- **Mã hóa** là thuật toán và khóa. Trong demo này là `AES-256-GCM` với khóa không thể export, nằm trong `AndroidKeyStore` / `TEE`.

Vân tay không biến plaintext thành ciphertext. Vân tay chỉ là điều kiện để phần cứng đồng ý dùng khóa.

### Mục tiêu demo

Một màn hình, hai chiều:

| Chiều | Việc người dùng thấy | Việc phần cứng làm |
| --- | --- | --- |
| A – Encrypt | Nhập ghi chú, chạm vân tay, lưu | `Cipher.doFinal` trong TEE, app chỉ nhận ciphertext + IV |
| B – Decrypt | Chạm vân tay, đọc lại ghi chú | TEE kiểm tra auth token rồi giải mã |

Inspector ở giữa màn hình luôn cho thấy thứ nằm trên đĩa: chuỗi Base64 vô nghĩa. Bản rõ `HELLO MOBILE` chỉ xuất hiện sau chiều B thành công.

### Góc nhìn Persuasive Computing

Mô hình hành vi Fogg: **B = MAP** (Behavior = Motivation × Ability × Prompt). Một hành vi bảo mật xảy ra khi đủ cả ba.

- **Motivation:** sinh viên muốn giữ nội dung ghi chú khỏi người khác mở máy.
- **Ability:** nếu mỗi lần mã hóa phải gõ passphrase dài, chi phí thao tác cao, người dùng tắt bảo mật hoặc dùng khóa yếu. Vân tay hạ chi phí Ability xuống một lần chạm.
- **Prompt:** `BiometricPrompt` hiện đúng lúc bấm mã hóa hoặc mở ghi chú, không phải một màn hình cài đặt nằm xa thao tác.

Demo này dùng Persuasive Computing để giải thích vì sao sản phẩm nên đưa sinh trắc học vào đúng điểm ma sát, **và** vì sao lớp thuyết phục đó không được thay cho mật mã. Icon vân tay cộng một biến `boolean` vẫn tạo cảm giác an toàn (Prompt và Ability vẫn có), nhưng attacker hook tầng ứng dụng thì bỏ qua được. `CryptoObject` giữ Ability thấp với người dùng thật, đồng thời buộc TEE tham gia mỗi lần dùng khóa.

---

## 2. Tổng quan công nghệ

### `AndroidKeyStore`

Kho khóa hệ thống. App nhận một handle `SecretKey`, không nhận raw key bytes. Alias cố định: `se405_student_vault_key`. Thông số tạo khóa trong `CryptoManager`:

- Thuật toán `AES`, kích thước 256 bit.
- Block mode `GCM`, padding `NoPadding`, transformation `AES/GCM/NoPadding`.
- `setUserAuthenticationRequired(true)`: KeyMint từ chối dùng khóa nếu chưa có xác thực người dùng.
- `setInvalidatedByBiometricEnrollment(true)`: đổi tập vân tay trong Settings thì khóa hỏng vĩnh viễn.
- Xác thực **từng lần dùng**:
  - API 30+ (`Build.VERSION_CODES.R`): `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`. Timeout `0` nghĩa là mỗi operation cần một lần xác thực. Chỉ `BIOMETRIC_STRONG` (Class 3) mới ký được auth token cho khóa này.
  - API 24–29: `setUserAuthenticationValidityDurationSeconds(-1)`, tương đương “mỗi lần dùng”.

`minSdk` là 24 vì `setInvalidatedByBiometricEnrollment` có từ Android 7.0. Máy demo nên là API 30 trở lên để đi nhánh `setUserAuthenticationParameters`.

### `TEE` (Trusted Execution Environment)

Vùng thực thi tách khỏi Android OS và khỏi process của app. Trên các bản Android hiện tại, vai trò này do **KeyMint** (trước đây là Keymaster) đảm nhiệm, thường chạy trong TEE. Cảm biến vân tay xác thực trong đường tin cậy và phát **HardwareAuthToken**. KeyMint chỉ giải mã key blob và chạy AES khi token khớp chính sách của khóa (loại authenticator, thời hạn, authenticator id).

App có thể bị debug hoặc bị hook. TEE không giao key material cho process đó.

### `AES-256-GCM`

`AES` khóa 256 bit ở mode `GCM` cung cấp cả bí mật và toàn vẹn. AndroidKeyStore tự sinh IV ngẫu nhiên khi `Cipher.init(ENCRYPT_MODE)`. `Cipher.doFinal` trả về ciphertext **kèm authentication tag 128 bit**. App lưu nguyên blob đó cùng IV. Sai IV, sửa một byte ciphertext, hoặc dùng nhầm khóa thì `doFinal` ở chiều giải mã ném `BadPaddingException` / `AEADBadTagException`. IV không phải bí mật, nhưng không được tái sử dụng cho cùng một khóa. Mỗi lần mã hóa tạo IV mới.

### `BiometricPrompt` và `CryptoObject`

`BiometricPrompt` là UI xác thực thống nhất (thay `FingerprintManager`). `CryptoObject` bọc đúng instance `Cipher` đã `init` bằng khóa của Keystore.

Điểm bắt buộc của demo: `authenticate(promptInfo, cryptoObject)`. Trong `onAuthenticationSucceeded`, chỉ gọi `doFinal` trên `result.getCryptoObject().getCipher()`. Không có cờ `isAuthenticated` để mở khóa logic.

`PromptInfo` chỉ cho `BIOMETRIC_STRONG` và có nút **Hủy**. Khóa không nhận device credential (PIN). PIN vẫn cần để *đăng ký* vân tay trong Settings, nhưng PIN không giải mã vault.

### Lưu trữ

`VaultStorage` ghi `SharedPreferences` tên `se405_student_vault`:

- `ciphertext`: Base64 flag `NO_WRAP`
- `iv`: Base64 flag `NO_WRAP`

Backup đám mây và device-transfer bị tắt (`allowBackup=false` và rule loại file prefs này). Reset xóa alias trong Keystore **và** xóa prefs. Khóa mới không giải được ciphertext cũ, nên hai thứ phải đi cùng nhau.

---

## 3. Cơ chế hoạt động (Internal Mechanism)

Sơ đồ hai chiều, vì sao `CryptoObject` mới là cổng TEE, và chỗ `KeyPermanentlyInvalidatedException` nổ nằm ở [FINGERPRINT_FLOW.md](FINGERPRINT_FLOW.md) mục 2. File đó trích đúng method và số dòng trong `CryptoManager.java`, `MainActivity.java`, `VaultStorage.java`.

Tóm tắt để đọc nhanh:

- Encrypt: `getEncryptCipher` → `authenticate(prompt, CryptoObject)` → `doFinal` chỉ trong `onAuthenticationSucceeded` → lưu Base64(IV) và Base64(ciphertext).
- Decrypt: `getDecryptCipher(iv)` → cùng đường `CryptoObject` → `doFinal` ra plaintext.
- Đổi vân tay trong Settings làm `Cipher.init` ném `KeyPermanentlyInvalidatedException` trước khi dialog mở. Alias và ciphertext vẫn còn. Reset xóa cả hai.

---

## 4. Hướng dẫn cài đặt và chạy trên Emulator

### Yêu cầu

- Android Studio có SDK API 35 (project `compileSdk` / `targetSdk` 35).
- JDK 17 trở lên để chạy Gradle. Android Studio dùng JDK đi kèm là đủ.
- Máy ảo **API 30 trở lên**. Nên dùng API 34 hoặc 35, system image Google APIs, form factor là điện thoại. Image Android TV không phù hợp để demo vân tay.
- `minSdk` 24. Đừng hạ thấp hơn: `setInvalidatedByBiometricEnrollment` sẽ không còn API để gọi.

Mở **đúng thư mục** chứa `settings.gradle` bằng Android Studio, để Gradle sync, rồi Run cấu hình `app`. Ngôn ngữ nguồn là Java. Layout là `res/layout/activity_main.xml`, ánh xạ view bằng `findViewById`. Không bật ViewBinding hay Compose.

Build từ terminal, tại thư mục gốc project:

```bat
gradlew.bat assembleDebug
```

APK debug: `app/build/outputs/apk/debug/app-debug.apk`.

### Tạo máy ảo

1. Device Manager → Create Virtual Device → chọn một máy Phone (ví dụ Pixel 6).
2. System image API 30+ (khuyến nghị API 34 hoặc 35) có Google APIs. Tải image nếu máy chưa có.
3. Finish, rồi chạy AVD.
4. Kiểm tra adb thấy đúng một emulator:

```bat
adb devices
```

### Đăng ký vân tay mẫu

Fingerprint trên emulator chỉ hoạt động sau khi máy đã có khóa màn hình.

1. Settings → đặt PIN hoặc password.
2. Vào màn đăng ký vân tay. Đường dẫn đổi theo đời Android:
   - API 30: **Settings → Security → Fingerprint**
   - API 33 trở đi, ảnh Pixel: **Settings → Security & privacy → Device unlock → Fingerprint**
3. Khi wizard báo chạm cảm biến, chạy lệnh dưới đây **nhiều lần** cho đến khi đăng ký xong. Chỉ đăng ký finger id `1` trước buổi demo. Finger id `2` để dành cho ca chạm sai.

```bat
adb -e emu finger touch 1
```

`-e` nghĩa là “emulator đang chạy, nếu chỉ có một máy”. Cắm thêm điện thoại thật thì lệnh này vẫn nhằm vào emulator.

4. Cài app (Run trong Android Studio, hoặc `adb install -r` file APK ở trên).
5. Mở **Secure Student Vault**. Ô nhập đã có sẵn `HELLO MOBILE`.

Nếu bấm mã hóa mà thấy khung cam “CHƯA SẴN SÀNG”, máy chưa có `BIOMETRIC_STRONG`. Quay lại bước đăng ký. Khóa Keystore gắn `AUTH_BIOMETRIC_STRONG` sẽ không được tạo khi chưa có vân tay Class 3. Vân tay emulator thuộc lớp này. Face unlock Class 2 trên một số máy thật thì không.

---

## 5. Kịch bản Test và Demo trên lớp

Ba ca, bảng code path, kết quả đã đo trên emulator API 37, và 22 lưu ý lúc implement nằm ở [FINGERPRINT_FLOW.md](FINGERPRINT_FLOW.md) mục 3 và 4.

Lệnh trên lớp:

```bat
adb -e emu finger touch 1
adb -e emu finger touch 2
```

`touch 1` là vân tay đã đăng ký. `touch 2` chỉ là vân tay sai khi **chưa** enroll id 2. Enroll id 2 là bước làm khóa tự hủy, không phải bước chạm sai.

Thứ tự 5 phút: mã hóa `HELLO MOBILE` và chiếu inspector → giải mã khung xanh → `touch 2` ra `ACCESS DENIED` → thêm vân tay rồi Decrypt ra cảnh báo đỏ đậm → Reset. Chi tiết từng bước và counter `acceptCrypto` / `rejectCrypto` ở file kỹ thuật.
