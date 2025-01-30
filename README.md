# Network Scanner

## Proje Amacı
Bu program, ağ üzerinde host keşfi ve port taraması yapabilen kapsamlı bir ağ tarama aracıdır. ARP ve ICMP protokollerini kullanarak hem yerel ağda hem de uzak ağlarda tarama yapabilmektedir. Program, ağ güvenliği testleri ve network yönetimi için geliştirilmiştir.

## Takım Üyeleri
- 2320191018 - Eren ERGÜN
- 2320191010 - İbrahim Yiğit Çetin

## Teslim Tarihi
28 Ocak 2025

## Gereksinimler

### Kütüphaneler ve Versiyonları
```
python >= 3.8
scapy == 2.5.0
ipaddress == 1.0.23
```

### Gerekli Araçlar
- Python 3.8 veya üzeri
- Root/Administrator yetkileri
- Linux/Unix tabanlı işletim sistemi (Windows için WSL gerekli)

## Kurulum

1. Repository'yi klonlayın:
```bash
git clone https://github.com/[kullanici-adi]/network-scanner.git
cd network-scanner
```

2. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

## Kullanım

Program root/administrator yetkileri ile çalıştırılmalıdır:

```bash
sudo python3 scanner.py
```

### Ana Menü Seçenekleri

1. ARP ile Tarama (Yerel Ağ)
2. ICMP ile Tarama (Tüm Ağlar)
3. Çıkış

### Alt Menü Seçenekleri

Her tarama tipi için:
1. Tek Host Tarama
2. Liste Tarama
   - Hazır Liste Var
   - Hazır Liste Oluştur
3. Geri

## IP Giriş Formatları
- Tekil IP: `192.168.1.1`
- CIDR notasyonu: `192.168.1.0/24`
- IP aralığı: `192.168.1.1-192.168.1.10`
- Son oktet aralığı: `192.168.1.0-13`

## Çıktı Dosyaları

### hosts.txt
Program çalıştırıldığında oluşturulan temel rapor dosyası aşağıdaki bilgileri içerir:
- Tarama başlangıç zamanı
- Tarama bitiş zamanı
- Toplam süre
- Tarama tipi
- Taranan IP aralığı
- Aktif host listesi

### scan_report_[tarih].txt
Detaylı tarama raporu aşağıdaki bölümleri içerir:
- Tarama bilgileri
  - Tarama tipi
  - Taranan IP aralığı
  - Başlama/bitiş zamanları
  - Toplam tarama süresi
- Aktif hostlar
  - Toplam aktif host sayısı
  - Host IP listesi
- Port bilgileri
  - Her host için açık port listesi

## Program Özellikleri

### Tarama Modları
1. ARP Taraması (Yerel ağ)
2. ICMP Taraması (Tüm ağlar)

### Optimizasyonlar
- Çoklu thread desteği
- Paralel tarama
- Akıllı timeout mekanizması

## Güvenlik Notları
- Program root/administrator yetkileri gerektirir
- Sadece yetkili olduğunuz ağlarda kullanın
- Test ortamlarında kullanmanız önerilir

## Hata Giderme

1. **Yetersiz Yetki Hatası**
   ```
   Bu program root/administrator yetkileri gerektirir!
   ```
   Çözüm: Programı `sudo` ile çalıştırın

2. **Geçersiz IP Format Hatası**
   - IP adresinin doğru formatta olduğundan emin olun
   - Desteklenen formatları kullanın

## Lisans
Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasını inceleyebilirsiniz.

## İletişim
Sorularınız ve önerileriniz için GitHub üzerinden issue açabilir veya pull request gönderebilirsiniz.