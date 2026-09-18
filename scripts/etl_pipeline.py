import json
import hashlib
import os
from datetime import datetime, timezone

DATA_FILE = "data/threats.json"
OUTPUT_DIR = "dist"

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest().lower()

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    if not os.path.exists(DATA_FILE):
        print(f"No se encontró {DATA_FILE}")
        return

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        threats = json.load(f)

    # Estructuras de salida
    k_prefixes = {}
    csv_lines = ["phone_number,threat_type,risk_level,reported_date"]

    for item in threats:
        phone = item.get("phone", "").strip()
        threat_type = item.get("type", "DESCONOCIDO")
        risk = item.get("risk", 80)
        date = item.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))

        if not phone:
            continue

        # 1. Registro CSV para lista pública abierta
        csv_lines.append(f"{phone},{threat_type},{risk},{date}")

        # 2. Generación de K-Anonimato (SHA-256)
        h = sha256_hash(phone)
        prefix = h[:5]   # Primeros 5 caracteres hexadecimales
        suffix = h[5:]   # Resto del hash

        if prefix not in k_prefixes:
            k_prefixes[prefix] = []

        k_prefixes[prefix].append({
            "suffix": suffix,
            "type": threat_type,
            "risk": risk
        })

    # Guardar CSV público
    with open(os.path.join(OUTPUT_DIR, "blocklist.csv"), "w", encoding="utf-8") as f:
        f.write("\n".join(csv_lines))

    # Guardar JSON con K-Anonimato para la app Android
    with open(os.path.join(OUTPUT_DIR, "k_prefixes.json"), "w", encoding="utf-8") as f:
        json.dump(k_prefixes, f, indent=2)

    # Metadatos del feed
    metadata = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total_signatures": len(threats),
        "source": "Mexico Telecom Threat Intel - Public Community Feed"
    }
    with open(os.path.join(OUTPUT_DIR, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"ETL finalizado con éxito: {len(threats)} números procesados.")

if __name__ == "__main__":
    main()
