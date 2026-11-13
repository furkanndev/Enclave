# Changelog

All notable changes to Enclave are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.1] - 2026-11-13

A maintenance release focused on user interface stability: overflow, clipping, and alignment fixes across the application, plus automated layout regression tests.

### Fixed
- **Password manager**
  - Long entry titles are elided to a single line instead of wrapping into a narrow column.
  - Password, two-factor (TOTP), and notes cards no longer overlap; stale fields are removed immediately when switching entries.
  - Removed the horizontal scrollbar in the entry list; copy buttons render correctly and stay in place.
  - Long passwords wrap in narrow panels; long URLs and usernames are elided with a tooltip.
  - Entry actions moved below the header so they never compete with the title for space.
  - Sidebar and list pane widened so action buttons are no longer clipped.
- **Dialogs**
  - Windows now size themselves to their content and enforce the minimum width their content needs, so nothing is silently cut off when resized.
  - Long checkbox and radio labels (password generator, export) split into a title and a hint.
  - Settings "This vault" tab no longer overflows horizontally.
- **Unlock screen**
  - Right-hand column scrolls instead of squashing the form on small windows.
  - Remember-vault and security-policy controls are no longer clipped at the minimum window size.
- **Workspace:** empty-vault action cards reserve enough height for their description text.

### Added
- Layout regression tests (`test_enclave_layout.py`, `test_enclave_layout_matrix.py`) that open the application windows in Turkish and English at several sizes and fail on clipped text, overflowing widgets, or unexpected horizontal scrolling. Set `ENCLAVE_FULL_MATRIX=1` to run the exhaustive style/color/mode matrix.

### Changed
- Refreshed the README screenshots and documentation.

### Türkçe

Arayüz kararlılığına odaklanan bakım sürümü: uygulama genelinde taşma, kırpılma ve hizalama sorunları düzeltildi, otomatik yerleşim regresyon testleri eklendi.

**Düzeltmeler**
- **Şifre yöneticisi:** Uzun başlıklar tek satırda "…" ile kısalıyor. Parola, TOTP ve not kartları üst üste binmiyor. Kayıt listesindeki yatay kaydırma kaldırıldı. Uzun parolalar satır kırıyor, uzun URL ve kullanıcı adları kısaltılıp ipucu gösteriliyor. Kayıt eylemleri başlığın altına taşındı, kenar çubuğu ve liste paneli genişletildi.
- **Diyaloglar:** Pencereler içeriğine göre boyutlanıyor ve gereken en küçük genişliği koruyor. Uzun onay kutusu ve seçenek metinleri başlık ve açıklamaya ayrıldı. Ayarlar'daki "Bu kasa" sekmesi yatay taşmıyor.
- **Kilit ekranı:** Küçük pencerede sağ sütun kaydırılabiliyor, "Kasayı hatırla" ve güvenlik politikası ayarları kırpılmıyor.
- **Çalışma alanı:** Boş kasa ekranındaki eylem kartları açıklama metni için yeterli yüksekliği ayırıyor.

**Eklenenler**
- Pencereleri Türkçe ve İngilizce, birkaç boyutta açıp kırpılan metin, taşan öğe ve beklenmeyen yatay kaydırmayı yakalayan yerleşim regresyon testleri (`ENCLAVE_FULL_MATRIX=1` ile tüm stil/renk/mod matrisi çalışır).

**Değişenler**
- README ekran görüntüleri ve dokümantasyon yenilendi.

## [2.0.0]

Initial release of Enclave v2.0: zero-knowledge encrypted vault and integrated password manager.
