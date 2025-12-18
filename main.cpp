#include <iostream>
#include <pcap.h>
#include <winsock2.h>
#include <string>
#include <ctime>
#include <algorithm>
#include "sqlite3.h"

typedef struct ip_header {
    unsigned char  ver_ihl; unsigned char  tos; unsigned short tlen; unsigned short identification;
    unsigned short flags_fo; unsigned char  ttl; unsigned char  proto; unsigned short crc;
    unsigned char  saddr[4]; unsigned char  daddr[4]; unsigned int   op_pad;
} ip_header;

typedef struct tcp_header {
    unsigned short src_port; unsigned short dst_port; unsigned int   seq; unsigned int   ack;
    unsigned char  data_offset; unsigned char  flags; unsigned short window; unsigned short checksum; unsigned short urgent_ptr;
} tcp_header;

sqlite3* db;

std::string get_service_name(int port) {
    switch (port) {
        case 80: return "HTTP"; case 443: return "HTTPS"; case 53: return "DNS";
        case 21: return "FTP"; case 22: return "SSH"; case 3306: return "MySQL";
        default: return "-";
    }
}


std::string get_country_code(std::string ip) {
    if (ip.find("192.168.") == 0) return "LOCAL (EV)";
    if (ip.find("10.") == 0) return "LOCAL (LAN)";
    if (ip.find("127.0.0.1") == 0) return "LOCALHOST";

    if (ip.find("142.250.") == 0 || ip.find("172.217.") == 0 || ip.find("8.8.") == 0) return "USA (Google)";

    if (ip.find("104.") == 0 || ip.find("172.") == 0) return "USA (Cloud)";

    if (ip.find("157.240.") == 0) return "IRL (Facebook)";

    if (ip.find("185.") == 0 || ip.find("31.") == 0) return "EU (Avrupa)";

    if (ip.find("88.") == 0 || ip.find("78.") == 0 || ip.find("212.") == 0) return "TR (Turkey)";

    return "INT (Dunya)";
}

void init_db() {
    int rc = sqlite3_open("sentinal.db", &db);
    if (rc) {
        std::cerr << "Veritabani hatasi: " << sqlite3_errmsg(db) << std::endl;
        return;
    } else {
        std::cout << "[+] Veritabani (v2) baglantisi basarili." << std::endl;
    }

    const char* sql = "CREATE TABLE IF NOT EXISTS logs ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "time TEXT,"
                      "src_ip TEXT,"
                      "src_port INTEGER,"
                      "dst_ip TEXT,"
                      "dst_port INTEGER,"
                      "country TEXT,"
                      "service TEXT,"
                      "size INTEGER,"
                      "is_threat INTEGER);";

    char* errMsg = 0;
    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "Tablo Hatasi: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

void save_to_db(std::string time, std::string src_ip, int src_port, std::string dst_ip, int dst_port, std::string country, std::string service, int size, int is_threat) {
    char* errMsg = 0;

    std::string sql = "INSERT INTO logs (time, src_ip, src_port, dst_ip, dst_port, country, service, size, is_threat) VALUES ('" +
                      time + "', '" + src_ip + "', " + std::to_string(src_port) + ", '" +
                      dst_ip + "', " + std::to_string(dst_port) + ", '" + country + "', '" + service + "', " +
                      std::to_string(size) + ", " + std::to_string(is_threat) + ");";

    int rc = sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL Hatasi: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct tm *ltime; char timestr[16]; time_t local_tv_sec;
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    char datestr[16]; strftime(datestr, sizeof datestr, "%Y-%m-%d", ltime);
    std::string full_date = std::string(datestr) + " " + std::string(timestr);

    ip_header *ih = (ip_header *) (pkt_data + 14);
    int ip_len = (ih->ver_ihl & 0xf) * 4;

    if (ih->proto == 6) { // TCP
        tcp_header *th = (tcp_header *) ((u_char*)ih + ip_len);
        int sport = ntohs(th->src_port);
        int dport = ntohs(th->dst_port);
        int tcp_len = (th->data_offset >> 4) * 4;
        u_char *payload = (u_char *)((u_char*)th + tcp_len);
        int payload_len = header->len - (14 + ip_len + tcp_len);

        std::string service = get_service_name(dport);
        if (service == "-") service = get_service_name(sport);

        int is_threat = 0;
        if (payload_len > 0) {
            std::string content(reinterpret_cast<const char*>(payload), payload_len);
            std::string lower_content = content;
            for(char &c : lower_content) c = tolower(c);
            if (lower_content.find("pass") != std::string::npos || lower_content.find("admin") != std::string::npos) {
                service = service + " [TEHLIKE]";
                is_threat = 1;
                std::cout << "!!! SALDIRI TESPIT EDILDI !!!" << std::endl;
            }
        }

        char src_ip[16], dst_ip[16];
        sprintf(src_ip, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
        sprintf(dst_ip, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);

        std::string country = get_country_code(dst_ip);

        std::cout << "[" << timestr << "] " << src_ip << " -> " << dst_ip << " (" << country << ") | " << service << std::endl;

        save_to_db(full_date, src_ip, sport, dst_ip, dport, country, service, header->len, is_threat);
    }
}

int main() {
    init_db();
    pcap_if_t *alldevs; pcap_if_t *d; int inum; int i = 0; pcap_t *adhandle; char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&alldevs, errbuf);
    for (d = alldevs; d; d = d->next) std::cout << ++i << ". " << (d->description ? d->description : "Isimsiz") << std::endl;
    if (i==0) return -1;
    std::cout << "Wi-Fi kartini sec (Numara): "; std::cin >> inum;
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    std::cout << "\n[+] Sentinal GeoIP Modu Aktif..." << std::endl;
    pcap_freealldevs(alldevs);
    pcap_loop(adhandle, 0, packet_handler, NULL);
    sqlite3_close(db);
    return 0;
}