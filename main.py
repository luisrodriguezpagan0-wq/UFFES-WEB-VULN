import urllib.request
import urllib.error
import ssl
import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse

RED = "\033[91m"
WHITE = "\033[97m"
GREEN = "\033[92m"
RESET = "\033[0m"

REPORTS = "reports"
os.makedirs(REPORTS, exist_ok=True)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protección HTTPS",
    "Content-Security-Policy": "Política de contenido",
    "X-Frame-Options": "Protección contra clickjacking",
    "X-Content-Type-Options": "Protección MIME",
    "Referrer-Policy": "Control de referencias",
    "Permissions-Policy": "Control de permisos"
}

def banner():
    os.system("clear")
    print(RED + """
       [-----]
       | o o |
       |  ^  |
       | \_/ |
       [-----]

    UFFES WEB VULN SCANNER
    PASSIVE SECURITY ANALYSIS
    """ + RESET)

def analyze(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print(RED + "URL no válida." + RESET)
        return

    if parsed.username or parsed.password:
        print(RED + "No introduzcas credenciales en la URL." + RESET)
        return

    print(WHITE + "\n[+] Consultando la web..." + RESET)

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "UFFES-WebScanner/1.0"}
    )

    result = {
        "url": url,
        "fecha": datetime.now().isoformat(),
        "estado": None,
        "https": parsed.scheme == "https",
        "servidor": None,
        "cabeceras": {},
        "hallazgos": []
    }

    try:
        context = ssl.create_default_context()
        with urllib.request.urlopen(
            request, timeout=12, context=context
        ) as response:
            headers = response.headers
            result["estado"] = response.status
            result["servidor"] = headers.get("Server", "No divulgado")

            for header, description in SECURITY_HEADERS.items():
                value = headers.get(header)
                result["cabeceras"][header] = bool(value)

                if not value:
                    result["hallazgos"].append(
                        "No se encontró: " + description
                    )

            cookies = headers.get_all("Set-Cookie") or []
            for cookie in cookies:
                missing = []
                if "secure" not in cookie.lower():
                    missing.append("Secure")
                if "httponly" not in cookie.lower():
                    missing.append("HttpOnly")
                if "samesite" not in cookie.lower():
                    missing.append("SameSite")
                if missing:
                    result["hallazgos"].append(
                        "Cookie con atributos no observados: "
                        + ", ".join(missing)
                    )

            print(GREEN + "[+] Respuesta HTTP:", response.status, RESET)

    except urllib.error.HTTPError as e:
        result["estado"] = e.code
        result["hallazgos"].append("El servidor respondió con HTTP " + str(e.code))
    except Exception as e:
        result["hallazgos"].append("No se pudo completar la consulta: " + str(e))

    if not result["https"]:
        result["hallazgos"].append("La URL utiliza HTTP en lugar de HTTPS.")

    filename = datetime.now().strftime("report_%Y%m%d_%H%M%S")
    json_path = os.path.join(REPORTS, filename + ".json")
    txt_path = os.path.join(REPORTS, filename + ".txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("UFFES WEB SECURITY REPORT\n")
        f.write("=" * 32 + "\n")
        f.write("URL: " + url + "\n")
        f.write("Fecha: " + result["fecha"] + "\n")
        f.write("Estado HTTP: " + str(result["estado"]) + "\n")
        f.write("HTTPS: " + str(result["https"]) + "\n")
        f.write("Servidor: " + str(result["servidor"]) + "\n\n")
        f.write("CABECERAS DE SEGURIDAD\n")
        for name, present in result["cabeceras"].items():
            f.write(("[OK] " if present else "[!] ") + name + "\n")
        f.write("\nHALLAZGOS\n")
        for item in result["hallazgos"]:
            f.write("- " + item + "\n")

    print(WHITE + "\n========== INFORME ==========" + RESET)
    print("URL:", url)
    print("HTTP:", result["estado"])
    print("HTTPS:", result["https"])
    print("Servidor:", result["servidor"])
    print("\nHallazgos:")
    for item in result["hallazgos"]:
        print(RED + "[!] " + item + RESET)

    print(GREEN + "\n[+] Informe TXT:", txt_path)
    print("[+] Informe JSON:", json_path, RESET)

def history():
    files = sorted(os.listdir(REPORTS))
    files = [x for x in files if x.endswith(".txt")]
    if not files:
        print("Todavía no hay informes.")
        return
    for item in files:
        print("- " + item)

def main():
    while True:
        banner()
        print(WHITE + "[1] Analizar URL")
        print("[2] Ver historial")
        print("[0] Salir" + RESET)
        option = input(RED + "\nUFFES > " + RESET).strip()

        if option == "1":
            url = input("URL: ").strip()
            analyze(url)
            input("\nPulsa ENTER para continuar...")
        elif option == "2":
            history()
            input("\nPulsa ENTER para continuar...")
        elif option == "0":
            break
        else:
            print("Opción no válida.")
            input("ENTER...")

if __name__ == "__main__":
    main()
