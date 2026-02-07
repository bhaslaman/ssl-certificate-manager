# SSL Certificate Manager

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.0-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.11-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.109-green.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/Bootstrap-5.3-purple.svg" alt="Bootstrap">
  <img src="https://img.shields.io/badge/Docker-Ready-blue.svg" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

Web tabanli SSL sertifika yonetim araci. Format donusumleri, sertifika analizi ve olusturma islemlerini tek bir arayuzden yapabilirsiniz.

## v2.0.0 Yenilikler

### Yeni Ozellikler

- **JKS (Java KeyStore) Destegi**: PFX<->JKS, PEM->JKS donusumleri
- **URL SSL Kontrolu**: Herhangi bir web sitesinin SSL sertifikasini kontrol edin
- **Tema Destegi**: Koyu/Acik tema secenegi (localStorage'a kaydedilir)
- **SSL Yasam Dongusu Sayfasi**: Gorsel akis diyagrami ile sertifika yasam dongusunu anlayin
- **Dokumantasyon Sayfasi**: Format aciklamalari, donusum matrisi, API endpoint listesi
- **Guncelleme Kontrolu**: GitHub releases'dan otomatik guncelleme bildirimi

### Iyilestirmeler

- **Key Format Secenegi**: PKCS#8 (varsayilan) veya TraditionalOpenSSL formati secimi
- **PFX Split Export**: PFX'ten PEM'e donusumde ayri dosyalar olarak ZIP export
- **SSRF Korumasi**: URL kontrolunde ozel IP adresleri engellendi
- **Favicon**: Yeni shield-lock ikonu

---

## Ekran Goruntuleri

Ana sayfa uzerinden tum ozelliklere erisebilirsiniz:
- **Donustur**: Sertifika format donusumleri
- **Analiz Et**: Sertifika detaylarini goruntuleme
- **Olustur**: Yeni sertifika ve key olusturma
- **Kontrol**: URL SSL sertifika kontrolu
- **Yasam Dongusu**: SSL sertifika surecini anlayin
- **Dokumantasyon**: Format ve API referansi

## Ozellikler

### Format Donusumleri

| Kaynak | Hedef Formatlar |
|--------|-----------------|
| PFX/P12 | PEM, DER, CER, **JKS** |
| PEM | PFX, DER, CER, P7B, **JKS** |
| DER | PEM, CER |
| CER/CRT | PEM, DER, PFX |
| P7B | PEM |
| **JKS** | PFX |

**Yeni v2.0:** JKS (Java KeyStore) destegi eklendi. Tomcat, Java uygulamalari icin idealdir.

**Legacy Encryption Destegi:** RC2, 3DES, DES gibi eski sifreleme algoritmalari ile olusturulmus PFX dosyalarini da destekler.

### URL SSL Kontrolu (Yeni!)

- Herhangi bir web sitesinin SSL sertifikasini kontrol edin
- Sertifika gecerliligi ve kalan gun sayisi
- Subject/Issuer bilgileri
- SAN (Subject Alternative Names)
- Fingerprint bilgileri
- DNS cozumleme (opsiyonel)
- **SSRF korumasi** (ozel IP adresleri engellenir)

### Sertifika Analizi

- Subject / Issuer bilgileri
- Gecerlilik tarihleri (baslangic/bitis)
- Kalan gun sayisi hesaplama
- Serial number
- Fingerprint (SHA1, SHA256, MD5)
- SAN (Subject Alternative Names)
- Key Usage & Extended Key Usage
- Basic Constraints (CA durumu)
- Sertifika zinciri goruntuleme
- Self-signed sertifika tespiti

### Sertifika/Key Olusturma

- **Private Key**: RSA (2048/4096 bit), ECDSA (P-256/P-384)
- **CSR**: Certificate Signing Request olusturma
- **Self-Signed**: Otomatik imzali sertifika
- **CA Certificate**: Root/Intermediate CA sertifikasi
- **Key + Cert**: Tek adimda key ve sertifika

### Key Islemleri

- Private key cikarma (PFX'ten)
- Sertifika cikarma (PFX'ten)
- Key sifre ekleme/kaldirma
- Key-Sertifika esleme kontrolu
- **Key format secimi**: PKCS#8 veya TraditionalOpenSSL

### Tema Destegi (Yeni!)

- Koyu ve acik tema secenegi
- Tercih localStorage'a kaydedilir
- Sistem temasina uyum

## Teknoloji Stack

- **Backend:** Python 3.11 + FastAPI
- **SSL Islemleri:** cryptography + pyOpenSSL
- **JKS Islemleri:** OpenJDK 17 keytool
- **Frontend:** HTML5 + Bootstrap 5 + Vanilla JavaScript
- **Coklu Dil:** i18n destegi (Turkce/Ingilizce)
- **Container:** Docker + docker-compose

## Kurulum

### Gereksinimler

- Python 3.11+ veya Docker
- OpenSSL (sistemde kurulu)
- OpenJDK 17+ (JKS destegi icin - Docker'da dahil)

### Docker ile Kurulum (Onerilen)

```bash
# Repository'yi klonlayin
git clone https://github.com/bhaslaman/ssl-certificate-manager.git
cd ssl-certificate-manager

# Docker Compose ile baslatin
docker-compose up --build -d

# Tarayicide acin
# http://localhost:8000
```

### Python ile Kurulum

```bash
# Repository'yi klonlayin
git clone https://github.com/bhaslaman/ssl-certificate-manager.git
cd ssl-certificate-manager

# Virtual environment olusturun (opsiyonel)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate  # Windows

# Bagimliliklari yukleyin
pip install -r requirements.txt

# Uygulamayi baslatin
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

### Donusum Endpoints

| Method | Endpoint | Aciklama |
|--------|----------|----------|
| POST | `/api/convert/pfx-to-pem` | PFX -> PEM donusumu |
| POST | `/api/convert/pem-to-pfx` | PEM -> PFX donusumu |
| POST | `/api/convert/pem-to-der` | PEM -> DER donusumu |
| POST | `/api/convert/der-to-pem` | DER -> PEM donusumu |
| POST | `/api/convert/pem-to-p7b` | PEM -> P7B donusumu |
| POST | `/api/convert/p7b-to-pem` | P7B -> PEM donusumu |
| POST | `/api/convert/pfx-to-jks` | PFX -> JKS donusumu **(Yeni)** |
| POST | `/api/convert/jks-to-pfx` | JKS -> PFX donusumu **(Yeni)** |
| POST | `/api/convert/pem-to-jks` | PEM -> JKS donusumu **(Yeni)** |
| POST | `/api/convert/jks-aliases` | JKS alias listesi **(Yeni)** |
| POST | `/api/convert/extract-key` | PFX'ten private key cikar |
| POST | `/api/convert/extract-cert` | PFX'ten sertifika cikar |

### Analiz Endpoints

| Method | Endpoint | Aciklama |
|--------|----------|----------|
| POST | `/api/analyze/certificate` | Sertifika analizi |
| POST | `/api/analyze/csr` | CSR analizi |
| POST | `/api/analyze/chain` | Sertifika zinciri analizi |
| POST | `/api/analyze/verify-match` | Key-sertifika esleme kontrolu |

### Olusturma Endpoints

| Method | Endpoint | Aciklama |
|--------|----------|----------|
| POST | `/api/generate/private-key` | Private key olustur |
| POST | `/api/generate/csr` | CSR olustur |
| POST | `/api/generate/self-signed` | Self-signed sertifika |
| POST | `/api/generate/ca` | CA sertifikasi |
| POST | `/api/generate/key-and-cert` | Key + sertifika birlikte |

### Kontrol Endpoints (Yeni!)

| Method | Endpoint | Aciklama |
|--------|----------|----------|
| POST | `/api/check/url` | URL SSL sertifika kontrolu |

### Sistem Endpoints (Yeni!)

| Method | Endpoint | Aciklama |
|--------|----------|----------|
| GET | `/api/system/update-check` | Guncelleme kontrolu |
| GET | `/api/system/version` | Versiyon bilgisi |
| GET | `/health` | Saglik kontrolu |

## Proje Yapisi

```
ssl-certificate-manager/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI ana uygulama
│   ├── routers/
│   │   ├── convert.py          # Donusum API'leri
│   │   ├── analyze.py          # Analiz API'leri
│   │   ├── generate.py         # Olusturma API'leri
│   │   └── check.py            # URL kontrol API'leri (Yeni)
│   ├── services/
│   │   ├── converter.py        # Donusum is mantigi
│   │   ├── analyzer.py         # Analiz is mantigi
│   │   ├── generator.py        # Olusturma is mantigi
│   │   ├── jks_converter.py    # JKS donusum (Yeni)
│   │   └── ssl_checker.py      # SSL kontrol (Yeni)
│   ├── static/
│   │   ├── css/style.css
│   │   ├── js/app.js
│   │   └── favicon.svg         # (Yeni)
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── convert.html
│   │   ├── analyze.html
│   │   ├── generate.html
│   │   ├── check.html          # (Yeni)
│   │   ├── lifecycle.html      # (Yeni)
│   │   └── docs.html           # (Yeni)
│   └── i18n/
│       ├── tr.json             # Turkce ceviriler
│       └── en.json             # Ingilizce ceviriler
├── tests/
│   ├── test_converter.py
│   └── test_analyzer.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Kullanim Ornekleri

### cURL ile API Kullanimi

**Private Key Olusturma:**
```bash
curl -X POST http://localhost:8000/api/generate/private-key \
  -F "key_type=RSA-2048"
```

**Self-Signed Sertifika Olusturma:**
```bash
curl -X POST http://localhost:8000/api/generate/key-and-cert \
  -F "cn=example.com" \
  -F "o=My Organization" \
  -F "c=TR" \
  -F "key_type=RSA-2048" \
  -F "validity_days=365" \
  -F "san_dns=example.com,www.example.com"
```

**Sertifika Analizi:**
```bash
curl -X POST http://localhost:8000/api/analyze/certificate \
  -F "file=@certificate.pem"
```

**PFX'ten PEM'e Donusum (PKCS#8 format):**
```bash
curl -X POST http://localhost:8000/api/convert/pfx-to-pem \
  -F "file=@certificate.pfx" \
  -F "password=mypassword" \
  -F "key_format=pkcs8"
```

**PFX'ten JKS'e Donusum:**
```bash
curl -X POST http://localhost:8000/api/convert/pfx-to-jks \
  -F "file=@certificate.pfx" \
  -F "pfx_password=mypassword" \
  -F "jks_password=jkspassword" \
  -F "alias=myalias" \
  -o keystore.jks
```

**URL SSL Kontrolu:**
```bash
curl -X POST http://localhost:8000/api/check/url \
  -H "Content-Type: application/json" \
  -d '{"hostname": "google.com", "port": 443, "check_dns": true}'
```

## Test

```bash
# Testleri calistir
pytest tests/ -v

# Coverage ile
pytest tests/ --cov=app --cov-report=html
```

## Coklu Dil Destegi

Uygulama Turkce ve Ingilizce dillerini destekler. Dil degistirmek icin:
- URL'e `?lang=tr` veya `?lang=en` parametresi ekleyin
- Navbar'daki dil secicisini kullanin

## Guvenlik Notlari

- Bu uygulama development ve internal kullanim icin tasarlanmistir
- Production ortaminda HTTPS kullanin
- Hassas sertifikalari islerken dikkatli olun
- Uploaded dosyalar gecici olarak islenir ve saklanmaz
- URL kontrolunde SSRF korumasi aktiftir (ozel IP'ler engellenir)

## Degisiklik Gecmisi

### v2.0.0 (2024)
- JKS (Java KeyStore) destegi eklendi
- URL SSL kontrolu ozelligi eklendi
- Koyu/Acik tema destegi eklendi
- SSL yasam dongusu sayfasi eklendi
- Dokumantasyon sayfasi eklendi
- Guncelleme kontrolu ozelligi eklendi
- Key format secenegi eklendi (PKCS#8/Traditional)
- PFX split export ozelligi eklendi
- Favicon eklendi
- SSRF korumasi eklendi

### v1.0.0 (2024)
- Ilk surum
- PFX, PEM, DER, P7B format donusumleri
- Sertifika analizi
- Key/Sertifika olusturma
- Turkce/Ingilizce dil destegi

## Katkida Bulunma

1. Fork edin
2. Feature branch olusturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request acin

## Lisans

Bu proje MIT lisansi altinda lisanslanmistir. Detaylar icin [LICENSE](LICENSE) dosyasina bakin.

## Iletisim

- GitHub: [@bhaslaman](https://github.com/bhaslaman)

---

<p align="center">
  Made with Python & FastAPI
</p>
