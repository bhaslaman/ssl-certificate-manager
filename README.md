# SSL Certificate Manager

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.109-green.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/Bootstrap-5.3-purple.svg" alt="Bootstrap">
  <img src="https://img.shields.io/badge/Docker-Ready-blue.svg" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

Web tabanlı SSL sertifika yönetim aracı. Format dönüşümleri, sertifika analizi ve oluşturma işlemlerini tek bir arayüzden yapabilirsiniz.

## Ekran Görüntüleri

Ana sayfa üzerinden tüm özelliklere erişebilirsiniz:
- **Dönüştür**: Sertifika format dönüşümleri
- **Analiz Et**: Sertifika detaylarını görüntüleme
- **Oluştur**: Yeni sertifika ve key oluşturma

## Özellikler

### 🔄 Format Dönüşümleri

| Kaynak | Hedef Formatlar |
|--------|-----------------|
| PFX/P12 | PEM, DER, CER |
| PEM | PFX, DER, CER, P7B |
| DER | PEM, CER |
| CER/CRT | PEM, DER, PFX |
| P7B | PEM |

**Legacy Encryption Desteği:** RC2, 3DES, DES gibi eski şifreleme algoritmaları ile oluşturulmuş PFX dosyalarını da destekler.

### 🔍 Sertifika Analizi

- Subject / Issuer bilgileri
- Geçerlilik tarihleri (başlangıç/bitiş)
- Kalan gün sayısı hesaplama
- Serial number
- Fingerprint (SHA1, SHA256, MD5)
- SAN (Subject Alternative Names)
- Key Usage & Extended Key Usage
- Basic Constraints (CA durumu)
- Sertifika zinciri görüntüleme
- Self-signed sertifika tespiti

### 🔐 Sertifika/Key Oluşturma

- **Private Key**: RSA (2048/4096 bit), ECDSA (P-256/P-384)
- **CSR**: Certificate Signing Request oluşturma
- **Self-Signed**: Otomatik imzalı sertifika
- **CA Certificate**: Root/Intermediate CA sertifikası
- **Key + Cert**: Tek adımda key ve sertifika

### 🔑 Key İşlemleri

- Private key çıkarma (PFX'ten)
- Sertifika çıkarma (PFX'ten)
- Key şifre ekleme/kaldırma
- Key-Sertifika eşleşme kontrolü

## Teknoloji Stack

- **Backend:** Python 3.11 + FastAPI
- **SSL İşlemleri:** cryptography + pyOpenSSL
- **Frontend:** HTML5 + Bootstrap 5 + Vanilla JavaScript
- **Çoklu Dil:** i18n desteği (Türkçe/İngilizce)
- **Container:** Docker + docker-compose

## Kurulum

### Gereksinimler

- Python 3.11+ veya Docker
- OpenSSL (sistemde kurulu)

### 🐳 Docker ile Kurulum (Önerilen)

```bash
# Repository'yi klonlayın
git clone https://github.com/bhaslaman/ssl-certificate-manager.git
cd ssl-certificate-manager

# Docker Compose ile başlatın
docker-compose up --build -d

# Tarayıcıda açın
# http://localhost:8000
```

### 🐍 Python ile Kurulum

```bash
# Repository'yi klonlayın
git clone https://github.com/bhaslaman/ssl-certificate-manager.git
cd ssl-certificate-manager

# Virtual environment oluşturun (opsiyonel)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate  # Windows

# Bağımlılıkları yükleyin
pip install -r requirements.txt

# Uygulamayı başlatın
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

### Dönüşüm Endpoints

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/convert/pfx-to-pem` | PFX → PEM dönüşümü |
| POST | `/api/convert/pem-to-pfx` | PEM → PFX dönüşümü |
| POST | `/api/convert/pem-to-der` | PEM → DER dönüşümü |
| POST | `/api/convert/der-to-pem` | DER → PEM dönüşümü |
| POST | `/api/convert/pem-to-p7b` | PEM → P7B dönüşümü |
| POST | `/api/convert/p7b-to-pem` | P7B → PEM dönüşümü |
| POST | `/api/convert/extract-key` | PFX'ten private key çıkar |
| POST | `/api/convert/extract-cert` | PFX'ten sertifika çıkar |

### Analiz Endpoints

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/analyze/certificate` | Sertifika analizi |
| POST | `/api/analyze/csr` | CSR analizi |
| POST | `/api/analyze/chain` | Sertifika zinciri analizi |
| POST | `/api/analyze/verify-match` | Key-sertifika eşleşme kontrolü |

### Oluşturma Endpoints

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/generate/private-key` | Private key oluştur |
| POST | `/api/generate/csr` | CSR oluştur |
| POST | `/api/generate/self-signed` | Self-signed sertifika |
| POST | `/api/generate/ca` | CA sertifikası |
| POST | `/api/generate/key-and-cert` | Key + sertifika birlikte |

## Proje Yapısı

```
ssl-certificate-manager/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI ana uygulama
│   ├── routers/
│   │   ├── convert.py          # Dönüşüm API'leri
│   │   ├── analyze.py          # Analiz API'leri
│   │   └── generate.py         # Oluşturma API'leri
│   ├── services/
│   │   ├── converter.py        # Dönüşüm iş mantığı
│   │   ├── analyzer.py         # Analiz iş mantığı
│   │   └── generator.py        # Oluşturma iş mantığı
│   ├── static/
│   │   ├── css/style.css
│   │   └── js/app.js
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── convert.html
│   │   ├── analyze.html
│   │   └── generate.html
│   └── i18n/
│       ├── tr.json             # Türkçe çeviriler
│       └── en.json             # İngilizce çeviriler
├── tests/
│   ├── test_converter.py
│   └── test_analyzer.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Kullanım Örnekleri

### cURL ile API Kullanımı

**Private Key Oluşturma:**
```bash
curl -X POST http://localhost:8000/api/generate/private-key \
  -F "key_type=RSA-2048"
```

**Self-Signed Sertifika Oluşturma:**
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

**PFX'ten PEM'e Dönüşüm:**
```bash
curl -X POST http://localhost:8000/api/convert/pfx-to-pem \
  -F "file=@certificate.pfx" \
  -F "password=mypassword"
```

## Test

```bash
# Testleri çalıştır
pytest tests/ -v

# Coverage ile
pytest tests/ --cov=app --cov-report=html
```

## Çoklu Dil Desteği

Uygulama Türkçe ve İngilizce dillerini destekler. Dil değiştirmek için:
- URL'e `?lang=tr` veya `?lang=en` parametresi ekleyin
- Navbar'daki dil seçicisini kullanın

## Güvenlik Notları

- Bu uygulama development ve internal kullanım için tasarlanmıştır
- Production ortamında HTTPS kullanın
- Hassas sertifikaları işlerken dikkatli olun
- Uploaded dosyalar geçici olarak işlenir ve saklanmaz

## Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## İletişim

- GitHub: [@bhaslaman](https://github.com/bhaslaman)

---

<p align="center">
  Made with ❤️ using Python & FastAPI
</p>
