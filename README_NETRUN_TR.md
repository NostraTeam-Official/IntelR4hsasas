# IntelR4h — Netrun kurulum rehberi (Türkçe)

Bu paket, IntelR4h arayüzünü ve FastAPI sunucusunu tek web uygulaması olarak çalıştırmaya uygun hale getirir. Kök dizinde `main.py` ve `requirements.txt` bulunur; veritabanı için Netrun'ın kalıcı `/data` dizini mevcutsa SQLite dosyası oraya yazılır. Yerel Windows testinde dosya proje klasörüne yazılır.

## Netrun'a yayınlama

1. Bu ZIP'i çıkarma; Netrun'ın proje yükleme bölümüne ZIP arşivinin kendisini yükleyebilirsin. İstersen arşivi önce çıkarıp dosyaları GitHub repository'nin kök dizinine de koyabilirsin.
2. Netrun hesabında yeni bir web projesi oluşturup `IntelR4h_Netrun.zip` dosyasını veya GitHub repository'sini seç.
3. Platform otomatik algılamaz ve başlangıç komutu sorarsa şu komutu kullan:

   `python -m uvicorn main:app --host 0.0.0.0 --port $PORT`

4. Ortam değişkenleri/secrets sorulduğunda aşağıdakileri ekle:

   - `ENVIRONMENT` = `production`
   - `JWT_SECRET_KEY` = CMD'de `py -c "import secrets; print(secrets.token_urlsafe(48))"` ile yeni oluşturduğun gizli değer
   - `INTELR4H_SETUP_CODE` = yalnızca sana ait, tahmin edilmesi zor kurucu kodu

5. `DATABASE_URL` istenmiyorsa ayarlama; bu paket Netrun üzerinde `/data/intelr4h.db` kullanacak şekilde ayarlandı. Bir dış veritabanı adresi ayarlarsan varsayılan SQLite kullanılmaz.
6. Yayın tamamlanınca sitenin verdiği adresi aç. Sağlık kontrolü: `/api/health` yolu `{"ok": true, "name": "IntelR4h"}` döndürmelidir.

## Güvenlik notları

- Gerçek JWT anahtarını, kurucu kodunu, `.env` dosyasını veya veritabanını GitHub'a yükleme.
- Daha önce paylaşılan JWT anahtarını yeniden kullanma; yeni bir anahtar üret.
- Bu proje yalnızca izinle eklenen kendi kayıtlarını aramak içindir; gizli veya sızdırılmış kişisel verileri toplamaya yönelik değildir.
- Ücretsiz Netrun web projesi boşta kalınca uykuya geçebilir; ilk ziyaret birkaç saniye gecikebilir. Hizmet koşulları, kaynak limitleri ve veri yedekleme seçeneklerini yayınlamadan önce kontrol et. Önemli veriler için ayrıca yedek tut.
