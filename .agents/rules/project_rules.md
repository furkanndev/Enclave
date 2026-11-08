# Enclave - Proje Kuralları ve Geliştirme Yönergeleri

Bu dosyadaki kurallar proje üzerinde çalışan Antigravity yapay zeka asistanı için bağlayıcı ve zorunludur.

---

### 1. Her Prompt Sonrası Otomatik EXE Derleme
- Kullanıcının ilettiği her talep ve yapılan her kod değişikliği tamamlandığında, konuşma sonlandırılmadan önce mutlaka `python build_exe.py` komutu çalıştırılarak güncel çalıştırılabilir dosya (`dist/Enclave.exe`) derlenmelidir.
- Derleme işlemi sonucunda çıkış kodu 0 olmalı ve yeni derlenen paket doğrulanmalıdır.

---

### 2. Uygulama İçi Emojilerin Kaldırılması & Vektörel İkon Kullanımı
- Uygulama genelinde (ana pencere, diyaloglar, butonlar, durum etiketleri, menüler vb.) hiçbir gayriresmi veya renkli emoji (`⚡`, `🛑`, `🔓`, `⚪`, `🔴`, `🟢`, `✓`, `➔`, `▾` vb.) kullanılmamalıdır.
- Simgeler ve göstergeler için SVG tabanlı vektörel ikonlar (`enclave_custom_ui.py` içindeki `SVG_ICONS` ve `get_svg_icon(name, color, size)`) kullanılmalıdır.
- Durum metinlerinde gerektiğinde `[ONAYLANDI]`, `[BEKLENİYOR]`, `[GEÇERSİZ]` gibi profesyonel köşeli parantezli etiketler ve tipografik madde işaretleri (`•`) tercih edilmelidir.

---

### 3. Dinamik ve Duyarlı Pencere Boyutlandırma
- Ana pencere ve tüm diyalog pencereleri (`QDialog`) katı veya sabit (`setFixedSize`, katı minimum/maksimum) boyutlarla sınırlandırılmamalıdır.
- Tüm diyaloglarda kullanıcı pencereyi kenarlarından veya sağ alt köşeden büyütebilmeli (`apply_dynamic_geometry(...)` ve `QDialog` için `self.setSizeGripEnabled(True)` kullanılmalıdır; `QMainWindow` üzerinde `setSizeGripEnabled` çağrılmamalıdır).
- Tablolar, konsollar ve metin alanları pencere genişletildiğinde orantılı olarak büyüyebilmeli (`setSizePolicy(Expanding, Expanding)`, `addWidget(widget, stretch)`).

---

### 4. Üç Tasarım ve Renk Düzeni Uyumluluğu
- Şifreli kasa arayüzü (`enclave_app/`) tek tasarım ve altı renkle çalışır. Her rengin açık ve koyu paletinin tamamı desteklenmelidir.
- Renkler yalnızca `enclave_app/designs.py` içindeki paletlerden gelir; widget kodunda renk yazılmaz. `test_enclave_app.py` WCAG AA kontrastını denetler.
- Yeni davranış `workspace.py` içine tek yerde yazılır; tasarımlar yalnızca parçaları farklı dizer.
- Windows'a özel VHD penceresi (`ui.py`, `extra_dialogs.py`, `enclave_custom_ui.py`) eski dört temasını korur.
- Aşırı parlak neonlar, fosforlu çerçeveler ve çamur renkler kesinlikle kullanılmamalıdır.

---

### 4.1 Çapraz Platform
- `enclave_core.py`, `config.py`, `logger.py`, `totp_engine.py` ve `enclave_app/` Windows modüllerini (`winreg`, `ctypes.windll`, `engine`, `ui`) üst düzeyde içe aktaramaz.
- Windows'a özel kod yalnızca `sys.platform == "win32"` dalında, gerektiğinde yüklenir.

---

### 5. Sıfır Adli İz ve Güvenlik Öncelikli Mimari (Zero Forensic Traces & Security-First)
- **Asla Diske Şifresiz Veri / Küçük Resim / İkon Yazılamaz:** Kasa içindeki dosyaların (resimler, belgeler, uygulamalar vb.) simgeleri, önizlemeleri veya küçük resimleri kesinlikle diske (örn. `%TEMP%`, AppData vb.) unencrypted (şifresiz) PNG/JPG olarak önbelleklenemez. Tüm simge ve önizleme önbellekleri yalnızca oturum süresince RAM'de (`RAM-Only / Memory-Only`) tutulmalı; disk sızıntısı (CWE-312) oluşturulmamalıdır.
- **Tuzak Kasa (Decoy Vault) & İnkâr Edilebilirlik (Plausible Deniability) Dokunulmazlığı:** Gerçek kasa ile tuzak kasa arasında asla ortak disk izi, ortak simge önbelleği veya adli bilişim kalıntısı bırakılamaz. Bir saldırgan veya adli inceleme diski taradığında hiçbir şifresiz ipucuna ulaşamamalıdır.
- **Eksiksiz Geçici Dosya İmhası (100% Secure Wipe & Fsync):** Çalıştırma, dışarı sürükleme veya simge çıkarma amacıyla oluşturulan her türlü geçici dosya (`.tmp`, `.exe`, `pvault_view_*` vb.), kullanım tamamlandığında veya kilitlendiğinde doğrudan `os.remove` ile değil, dosya boyutunun **%100'ü sıfır baytlarla (`b"\x00"`) üzerine yazılarak ve `os.fsync` çağrısıyla diske zorlanarak** imha edilmelidir (`secure_wipe_file`). Kısmi sıfırlama veya atlama yapılamaz.
- **Bellek ve Önbellek Temizliği (Memory Hygiene):** Kasa kilitlendiğinde (`lock_and_close`), kapatıldığında (`closeEvent`) veya hata durumlarında; RAM'deki kriptografik anahtarlar (`auth_info`), katalog listeleri (`cached_files`), ve simge önbellekleri (`thumbnail_cache`) derhal boşaltılmalı, referansları silinmeli ve çöp toplayıcı çağrılmalıdır.
- **Artık Dosya Süpürme (Orphaned Temp Purge):** Uygulama açılışında ve kapanışında, önceki çökmelerden veya testlerden kalmış olabilecek tüm `%TEMP%\pvault_*` ve geçici artıklar otomatik olarak adli standartta güvenle sıfırlanıp silinmelidir.

---

### 6. Python GUI Profesyonel UI/UX Standartları
- Projedeki tüm arayüz geliştirmelerinde `.agents/rules/python_gui_standard.md` dosyasında tanımlanan 16 maddelik evrensel Python GUI standardı (Okunabilirlik, Kullanılabilirlik, Erişilebilirlik, Düzen Kararlılığı, Görsel Test Zorunluluğu) koşulsuz olarak uygulanmalıdır.

---

### 7. UI/UX ve Yerleşim (Layout) Kuralları
- **ASLA Sabit Boyut ve Mutlak Konumlandırma Kullanma:** Bileşenleri hizalamak için kesinlikle setFixedWidth, setFixedHeight, setFixedSize (ikon ve göstergeler hariç) veya katı piksel değerleri kullanılmamalıdır. Her zaman Qt yerleşim sistemleri (QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout) ve esnek QSizePolicy kullanılmalıdır.
- **Metin Taşmalarını ve İç İçe Geçmeleri Önle:** Tüm metin etiketlerinde ve açıklamalarda mutlaka setWordWrap(True) kullanılmalı veya metin alanlarına kaydırma desteği verilmelidir. Butonlara sabit yükseklik/genişlik vermek yerine iç boşluk (padding) verilmeli ve esnek min-width tanımlanmalıdır.
- **Kapsayıcı (Container) ve Boşluk Yönetimi:** Elemanların birbirine yapışmasını önlemek için her ana kapsayıcıda tutarlı spacing (setSpacing) ve iç kenar boşluğu (setContentsMargins) uygulanmalı; içerik taşmalarına karşı QScrollArea kullanılmalıdır.
- **Duyarlı (Responsive) Tasarım:** Tüm pencereler ve kartlar içindeki en uzun metne veya elemana göre esneyebilmeli, pencere genişletildiğinde orantılı olarak büyüyebilmelidir.
