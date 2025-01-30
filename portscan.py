import socket
import concurrent.futures
import os
import ipaddress
from scapy.all import *
import sys
from datetime import datetime
import time
import asyncio
import struct

# Scapy warning mesajlarını kapat
conf.verb = 0

def parse_ip_range(ip_input):
    """
    Parse IP range input in various formats:
    - Single IP: '192.168.1.1'
    - CIDR notation: '192.168.1.0/24'
    - IP range with dash: '192.168.1.1-192.168.1.10'
    - IP range with last octet range: '192.168.1.0-13'
    
    Returns a list of IP addresses
    """
    try:
        # Check for CIDR notation
        if '/' in ip_input:
            import ipaddress
            network = ipaddress.ip_network(ip_input, strict=False)
            return [str(ip) for ip in network.hosts()]
        
        # Check for range with dash
        if '-' in ip_input:
            # Split the input
            start, end = ip_input.split('-')
            
            # If only the last octet is specified
            if '.' not in end:
                # Parse the base IP and last octet range
                base_ip = '.'.join(start.split('.')[:-1])
                start_last = int(start.split('.')[-1])
                end_last = int(end)
                
                # Validate range
                if start_last > end_last:
                    start_last, end_last = end_last, start_last
                
                # Generate IP list
                return [f"{base_ip}.{i}" for i in range(start_last, end_last + 1)]
            
            # Full IP range
            import ipaddress
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
            
            # Validate range
            if start_ip > end_ip:
                start_ip, end_ip = end_ip, start_ip
            
            # Generate IP list
            return [str(ipaddress.ip_address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]
        
        # Single IP
        import ipaddress
        ipaddress.ip_address(ip_input)
        return [ip_input]
    
    except (ValueError, ipaddress.AddressValueError) as e:
        print(f"Hata: Geçersiz IP adresi formatı - {e}")
        return []

def create_detailed_report(tarama_tipi, ip_input, baslama_zamani, bitis_zamani, tarama_suresi, aktif_hostlar, port_bilgileri=None):
    """
    Detaylı tarama raporu oluşturur
    """
    # Raporun dosya adını oluştur (tarih ve saat içeren benzersiz bir ad)
    rapor_zamani = datetime.now().strftime("%Y%m%d_%H%M%S")
    rapor_dosya_adi = f"scan_report_{rapor_zamani}.txt"
    
    try:
        with open(rapor_dosya_adi, "w", encoding="utf-8") as rapor_dosyasi:
            # Rapor başlığı
            rapor_dosyasi.write("=" * 50 + "\n")
            rapor_dosyasi.write("      AĞ TARAMA RAPORU\n")
            rapor_dosyasi.write("=" * 50 + "\n\n")
            
            # Tarama Detayları
            rapor_dosyasi.write("TARAMA BİLGİLERİ\n")
            rapor_dosyasi.write("-" * 20 + "\n")
            rapor_dosyasi.write(f"Tarama Tipi: {tarama_tipi}\n")
            rapor_dosyasi.write(f"Taranan IP Aralığı: {ip_input}\n")
            rapor_dosyasi.write(f"Başlama Zamanı: {baslama_zamani}\n")
            rapor_dosyasi.write(f"Bitiş Zamanı: {bitis_zamani}\n")
            rapor_dosyasi.write(f"Toplam Tarama Süresi: {tarama_suresi}\n\n")
            
            # Aktif Hostlar
            rapor_dosyasi.write("AKTIF HOSTLAR\n")
            rapor_dosyasi.write("-" * 20 + "\n")
            if aktif_hostlar:
                rapor_dosyasi.write(f"Toplam Aktif Host Sayısı: {len(aktif_hostlar)}\n")
                for ip in aktif_hostlar:
                    rapor_dosyasi.write(f"- {ip}\n")
            else:
                rapor_dosyasi.write("Hiçbir aktif host bulunamadı.\n")
            
            # Port Bilgileri
            if port_bilgileri:
                rapor_dosyasi.write("\nPORT BİLGİLERİ\n")
                rapor_dosyasi.write("-" * 20 + "\n")
                for ip, portlar in port_bilgileri.items():
                    rapor_dosyasi.write(f"{ip} IP Adresinde Açık Portlar:\n")
                    if portlar:
                        for port in portlar:
                            rapor_dosyasi.write(f"  - {port}\n")
                    else:
                        rapor_dosyasi.write("  Açık port bulunamadı.\n")
            
            # Rapor sonlandırma
            rapor_dosyasi.write("\n" + "=" * 50 + "\n")
            rapor_dosyasi.write("    Rapor Sonu\n")
            rapor_dosyasi.write("=" * 50 + "\n")
        
        print(f"\nDetaylı rapor '{rapor_dosya_adi}' dosyasına kaydedildi.")
        return rapor_dosya_adi
    except Exception as e:
        print(f"Rapor oluşturulurken hata: {e}")
        return None

def send_icmp_packet(ip):
    try:
        # Raw socket oluştur
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(0.5)  # Kısa timeout

        # ICMP Echo Request paketi oluştur
        packet_id = os.getpid() & 0xFFFF
        packet_seq = 1
        
        # ICMP header oluştur
        header = struct.pack('!BBHHH', 8, 0, 0, packet_id, packet_seq)
        
        # Checksum hesapla
        checksum = calculate_checksum(header)
        header = struct.pack('!BBHHH', 8, 0, checksum, packet_id, packet_seq)
        
        # Paketi gönder
        sock.sendto(header, (ip, 0))
        
        try:
            # Yanıtı al
            sock.recvfrom(1024)
            sock.close()
            return ip
        except socket.timeout:
            sock.close()
            return None
        except Exception:
            sock.close()
            return None
    except Exception:
        return None

def calculate_checksum(data):
    """ICMP checksum hesaplama fonksiyonu"""
    if len(data) % 2 == 1:
        data += b'\0'
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    checksum = sum(words)
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return ~checksum & 0xFFFF

def parallel_host_discovery_arp(ip_list, thread_count=100):
    def arp_scan(ip):
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        paket = ether/arp
        result = srp(paket, timeout=1, verbose=0)[0]
        if result:
            return ip
        return None

    aktif_hostlar = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(arp_scan, ip) for ip in ip_list]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                aktif_hostlar.append(result)
                print(f"\nHost bulundu: {result}")
    
    return aktif_hostlar

def parallel_host_discovery_icmp_optimized(ip_list, thread_count=300):
    aktif_hostlar = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(send_icmp_packet, ip) for ip in ip_list]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                aktif_hostlar.append(result)
                print(f"\nHost bulundu: {result}")
    
    return aktif_hostlar

def optimized_port_scan(ip_adresi, thread_count=500):
    def tarama(ip_adresi, port_range):
        open_ports = []
        for port in port_range:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect((ip_adresi, port))
                open_ports.append(port)
                s.close()
            except:
                pass
        return open_ports

    port_ranges = []
    chunk_size = 65536 // thread_count
    for i in range(0, 65536, chunk_size):
        port_ranges.append(range(i, min(i + chunk_size, 65536)))

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(tarama, ip_adresi, port_range) 
                  for port_range in port_ranges]
        
        for future in concurrent.futures.as_completed(futures):
            for port in future.result():
                print(f"{ip_adresi}:{port} OPEN")
                open_ports.append(port)
    
    return open_ports

def otomatik_host_tarama(tarama_tipi):
    print("\nOtomatik Host Tarama Başlatılıyor...")
    
    while True:
        ip_input = input("IP aralığını giriniz (örn: 192.168.1.0/24, 192.168.1.1-10, 10.5.48.0-13): ")
        if ip_input.lower() == 'q':
            return
        
        ip_range = parse_ip_range(ip_input)
        
        if not ip_range:
            print("Geçersiz IP aralığı! Tekrar deneyin veya çıkmak için 'q' yazın.")
            continue
        
        print(f"\n{tarama_tipi} taraması başlatılıyor...")
        print(f"Toplam {len(ip_range)} adres taranacak...")
        
        baslama_zamani = datetime.now()
        
        if tarama_tipi == "ARP":
            aktif_hostlar = parallel_host_discovery_arp(ip_range)
        else:
            aktif_hostlar = parallel_host_discovery_icmp_optimized(ip_range)

        # Port bilgilerini saklamak için bir sözlük
        port_bilgileri = {}
        
        if aktif_hostlar:
            print("\nAktif hostlar için port taraması başlatılıyor...")
            for ip in aktif_hostlar:
                print(f"\n{ip} için port taraması yapılıyor...")
                open_ports = optimized_port_scan(ip)
                port_bilgileri[ip] = open_ports

        bitis_zamani = datetime.now()
        tarama_suresi = bitis_zamani - baslama_zamani

        if aktif_hostlar:
            # hosts.txt dosyasına kaydet
            with open("hosts.txt", "w") as f:
                f.write(f"Tarama Başlangıç: {baslama_zamani}\n")
                f.write(f"Tarama Bitiş: {bitis_zamani}\n")
                f.write(f"Toplam Süre: {tarama_suresi}\n")
                f.write(f"Tarama Tipi: {tarama_tipi}\n")
                f.write(f"Tarama Aralığı: {ip_input}\n")
                f.write("-" * 50 + "\n\n")
                
                for ip in aktif_hostlar:
                    f.write(f"{ip}\n")
            
            # Detaylı rapor oluştur
            create_detailed_report(
                tarama_tipi, 
                ip_input, 
                baslama_zamani, 
                bitis_zamani, 
                tarama_suresi, 
                aktif_hostlar, 
                port_bilgileri
            )
                    
            print(f"\nTarama tamamlandı! {len(aktif_hostlar)} aktif host bulundu.")
            print(f"Toplam tarama süresi: {tarama_suresi}")
            print("Sonuçlar hosts.txt dosyasına kaydedildi.")
        else:
            print("\nTarama tamamlandı! Aktif host bulunamadı.")

        break  # Döngüyü kır

def liste_tarama(dosya_yolu, tarama_tipi):
    if dosya_yolu.lower() == 'q':
        return False
        
    if not os.path.exists(dosya_yolu):
        print("HATA: Dosya bulunamadı!")
        return True

    if os.path.getsize(dosya_yolu) == 0:
        print("HATA: Dosya boş!")
        return True

    try:
        with open(dosya_yolu, 'r') as dosya:
            ipler = dosya.readlines()
    except Exception as e:
        print(f"HATA: Dosya okuma hatası: {e}")
        return True

    ip_list = [ip.strip() for ip in ipler if ip.strip()]
    print(f"\nToplam {len(ip_list)} IP adresi taranacak...")
    
    baslama_zamani = datetime.now()
    
    if tarama_tipi == "ARP":
        aktif_hostlar = parallel_host_discovery_arp(ip_list)
    else:
        aktif_hostlar = parallel_host_discovery_icmp_optimized(ip_list)
    
    # Port bilgilerini saklamak için bir sözlük
    port_bilgileri = {}
    
    if aktif_hostlar:
        print("\nAktif hostlar için port taraması başlatılıyor...")
        for ip in aktif_hostlar:
            print(f"\n{ip} için port taraması yapılıyor...")
            open_ports = optimized_port_scan(ip)
            port_bilgileri[ip] = open_ports
    
    bitis_zamani = datetime.now()
    tarama_suresi = bitis_zamani - baslama_zamani
    
    if aktif_hostlar:
        # hosts.txt dosyasına kaydet
        with open("hosts.txt", "w") as f:
            f.write(f"Tarama Başlangıç: {baslama_zamani}\n")
            f.write(f"Tarama Bitiş: {bitis_zamani}\n")
            f.write(f"Toplam Süre: {tarama_suresi}\n")
            f.write(f"Tarama Tipi: {tarama_tipi}\n")
            f.write(f"Kaynak Dosya: {dosya_yolu}\n")
            f.write("-" * 50 + "\n\n")
            
            for ip in aktif_hostlar:
                f.write(f"{ip}\n")
        
        # Detaylı rapor oluştur
        create_detailed_report(
            tarama_tipi, 
            dosya_yolu, 
            baslama_zamani, 
            bitis_zamani, 
            tarama_suresi, 
            aktif_hostlar, 
            port_bilgileri
        )
        
        print(f"\nTarama tamamlandı! {len(aktif_hostlar)} aktif host bulundu.")
        print(f"Toplam tarama süresi: {tarama_suresi}")
        print("Sonuçlar hosts.txt dosyasına kaydedildi.")
    else:
        print("\nTarama tamamlandı! Aktif host bulunamadı.")
    
    return True

def liste_tarama_menusu(tarama_tipi):
    while True:
        print(f"""
    Liste Tarama Menüsü ({tarama_tipi})
    1) Hazır Liste Var
    2) Hazır Liste Oluştur
    3) Geri
    """)
        secim = input("Seçiminizi yapın (1/2/3): ")
        
        if secim == "1":
            while True:
                dosya_yolu = input("Dosya yolunu giriniz (Çıkış için 'q'): ")
                devam_et = liste_tarama(dosya_yolu, tarama_tipi)
                if not devam_et:
                    break
        elif secim == "2":
            otomatik_host_tarama(tarama_tipi)
        elif secim == "3":
            break
        else:
            print("Geçersiz seçim! Lütfen tekrar deneyin.")

def main():
    if os.geteuid() != 0:
        print("Bu program root/administrator yetkileri gerektirir!")
        print("Lütfen 'sudo python3 scanner.py' komutu ile çalıştırın.")
        sys.exit(1)
        
    while True:
        print("""
    Port Tarama Programı
    1) ARP ile Tarama (Yerel Ağ)
    2) ICMP ile Tarama (Tüm Ağlar)
    3) Çıkış
    """)

        secim = input("Bir Seçim Yapınız (1/2/3): ")

        if secim == "1" or secim == "2":
            tarama_tipi = "ARP" if secim == "1" else "ICMP"
            
            while True:
                print(f"""
    {tarama_tipi} Tarama Menüsü
    1) Tek Host Tarama
    2) Liste Tarama
    3) Geri
                """)
                alt_secim = input("Seçiminizi yapın (1/2/3): ")
                
                if alt_secim == "1":
                    while True:
                        ip_adresi = input("IP adresini giriniz (Çıkış için 'q'): ")
                        if ip_adresi.lower() == 'q':
                            break
                        
                        print(f"\n{ip_adresi} için {tarama_tipi} kontrolü yapılıyor...")
                        if tarama_tipi == "ARP":
                            aktif_hostlar = parallel_host_discovery_arp([ip_adresi])
                        else:
                            aktif_hostlar = parallel_host_discovery_icmp_optimized([ip_adresi])
                        
                        # Port bilgilerini saklamak için bir sözlük
                        port_bilgileri = {}
                        
                        baslama_zamani = datetime.now()
                        
                        if aktif_hostlar:
                            print("\nAktif hostlar için port taraması başlatılıyor...")
                            for ip in aktif_hostlar:
                                print(f"\n{ip} için port taraması yapılıyor...")
                                open_ports = optimized_port_scan(ip)
                                port_bilgileri[ip] = open_ports

                        bitis_zamani = datetime.now()
                        tarama_suresi = bitis_zamani - baslama_zamani

                        if aktif_hostlar:
                            # hosts.txt dosyasına kaydet
                            with open("hosts.txt", "w") as f:
                                f.write(f"Tarama Başlangıç: {baslama_zamani}\n")
                                f.write(f"Tarama Bitiş: {bitis_zamani}\n")
                                f.write(f"Toplam Süre: {tarama_suresi}\n")
                                f.write(f"Tarama Tipi: {tarama_tipi}\n")
                                f.write(f"Tarama IP: {ip_adresi}\n")
                                f.write("-" * 50 + "\n\n")
                                
                                for ip in aktif_hostlar:
                                    f.write(f"{ip}\n")
                            
                            # Detaylı rapor oluştur
                            create_detailed_report(
                                tarama_tipi, 
                                ip_adresi, 
                                baslama_zamani, 
                                bitis_zamani, 
                                tarama_suresi, 
                                aktif_hostlar, 
                                port_bilgileri
                            )
                                    
                            print(f"\nTarama tamamlandı! {len(aktif_hostlar)} aktif host bulundu.")
                            print(f"Toplam tarama süresi: {tarama_suresi}")
                            print("Sonuçlar hosts.txt dosyasına kaydedildi.")
                        else:
                            print("\nTarama tamamlandı! Aktif host bulunamadı.")
                
                elif alt_secim == "2":
                    liste_tarama_menusu(tarama_tipi)
                
                elif alt_secim == "3":
                    break
                
                else:
                    print("Geçersiz seçim!")
                    
        elif secim == "3":
            print("Program sonlandırılıyor...")
            break
        
        else:
            print("Geçersiz seçim! Lütfen tekrar deneyin.")

if __name__ == "__main__":
    main()