#!/data/data/com.termux/files/usr/bin/bash
set -e
pkg update -y
pkg install -y python android-tools
termux-setup-storage || true
mkdir -p /sdcard/Download/X67_AntiRemote
chmod +x x67_antiremote.py
echo
echo "Instalação concluída."
echo "Execute: python x67_antiremote.py"
