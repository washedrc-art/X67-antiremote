#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "[X67] Atualizando Termux..."
pkg update -y
pkg upgrade -y

echo "[X67] Instalando Python, Git e ADB..."
pkg install -y python git android-tools

echo "[X67] Atualizando pip..."
python -m pip install --upgrade pip

echo "[X67] Instalando dependências Python..."
pip install -r requirements.txt --upgrade

chmod +x x67_antiremote.py

echo
echo "[OK] Instalação concluída."
echo "Agora conecte o ADB e execute:"
echo "  python x67_antiremote.py"
