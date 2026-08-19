from scapy.all import rdpcap, IP, TCP, UDP
import os

# Dicionário simples de assinaturas (Heurística baseada em portas conhecidas)
# Na vida real, isso seria substituído por uma API de Threat Intelligence ou regras YARA/Snort.
ASSINATURAS_MALWARE = {
    4444: "Metasploit/Meterpreter (Reverse Shell Padrão)",
    6667: "Possível Botnet (Comunicação IRC em texto claro)",
    1337: "Backdoor Genérico / Malware Antigo (Leet port)",
    3389: "RDP - Atenção: Possível tentativa de Força Bruta ou Ransomware",
    445:  "SMB - Atenção: Possível propagação de worms (ex: WannaCry, Conficker)",
    23:   "Telnet - Tráfego não criptografado, alvo comum de botnets IoT (Mirai)"
}

def traduzir_flags_tcp(flag_int):
    """Traduz o valor inteiro da flag TCP para um formato legível."""
    flags = {
        'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH', 
        'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
    }
    flag_str = str(flag_int)
    return ' | '.join([flags[x] for x in flag_str if x in flags])

def analisar_pcap(caminho_arquivo):
    if not os.path.exists(caminho_arquivo):
        print(f"Erro: Arquivo {caminho_arquivo} não encontrado.")
        return

    print(f"\n[{'*'*10}] Analisando: {caminho_arquivo} [{'*'*10}]\n")
    
    try:
        # Carrega o arquivo pcap na memória (Cuidado com arquivos muito grandes)
        pacotes = rdpcap(caminho_arquivo)
    except Exception as e:
        print(f"Erro ao ler o PCAP: {e}")
        return

    alertas = []

    for pacote in pacotes:
        # Analisa apenas pacotes que possuem a camada IP
        if IP in pacote:
            ip_origem = pacote[IP].src
            ip_destino = pacote[IP].dst
            protocolo = "Desconhecido"
            porta_origem = 0
            porta_destino = 0
            flags = "N/A"

            # Analisa a camada TCP
            if TCP in pacote:
                protocolo = "TCP"
                porta_origem = pacote[TCP].sport
                porta_destino = pacote[TCP].dport
                flags = traduzir_flags_tcp(pacote[TCP].flags)
                
            # Analisa a camada UDP
            elif UDP in pacote:
                protocolo = "UDP"
                porta_origem = pacote[UDP].sport
                porta_destino = pacote[UDP].dport

            # === MOTOR DE DETECÇÃO SIMPLES ===
            
            # 1. Checagem de Portas Suspeitas
            malware_detectado = ASSINATURAS_MALWARE.get(porta_destino) or ASSINATURAS_MALWARE.get(porta_origem)
            
            # 2. Checagem de anomalias em Flags TCP (Ex: Null Scan, Xmas Scan - usados para reconhecimento/ataque)
            if protocolo == "TCP":
                if pacote[TCP].flags == 0:
                    malware_detectado = "Anomalia: TCP Null Scan (Reconhecimento hostil)"
                elif pacote[TCP].flags == 0x29: # FIN, PSH, URG
                    malware_detectado = "Anomalia: TCP Xmas Scan (Reconhecimento hostil)"

            # Se algo suspeito for encontrado, adiciona ao log
            if malware_detectado:
                alerta = (
                    f"⚠️  ALERTA DE SEGURANÇA: {malware_detectado}\n"
                    f"    ├── Origem: {ip_origem}:{porta_origem}\n"
                    f"    ├── Destino: {ip_destino}:{porta_destino}\n"
                    f"    ├── Protocolo: {protocolo}\n"
                    f"    └── Flags TCP: {flags}\n"
                )
                if alerta not in alertas: # Evita flood do mesmo pacote exato
                    alertas.append(alerta)

    # Exibe os resultados
    if alertas:
        print(f"Foram encontradas {len(alertas)} atividades suspeitas:\n")
        for alerta in alertas:
            print(alerta)
    else:
        print("✅ Nenhuma atividade suspeita óbvia detectada com as regras atuais.")

if __name__ == "__main__":
    # Substitua pelo caminho do seu arquivo .pcap
    arquivo_alvo = "seu_arquivo_de_trafego.pcap" 
    analisar_pcap(arquivo_alvo)