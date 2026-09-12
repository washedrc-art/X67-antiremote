# X67 AntiRemote — versão corrigida

Scanner de integridade/forense para análise autorizada de Android usando Termux + ADB.

## Instalação

```bash
pkg update -y
pkg install -y python android-tools
termux-setup-storage
cd X67-AntiRemote-fixed
python x67_antiremote.py
```

## ADB

Antes da análise, confirme:

```bash
adb devices
```

O aparelho deve aparecer como `device`.

## Relatórios

Tudo é gravado diretamente no armazenamento compartilhado:

`/sdcard/Download/X67_AntiRemote/`

O relatório HTML principal também é criado em:

`/sdcard/Download/x67_scanner_report.html`

Não é usado `~/x67_antiremote`, nem uma pasta interna de `data/data` para os relatórios.

## Arquivos

- `x67_antiremote.py` — scanner principal
- `X67.php` — iniciador opcional e gerador de HTML
- `install.sh` — instalação
- `run.sh` — execução rápida
- `requirements.txt` — sem dependências Python externas

Use somente em aparelhos e dados que você está autorizado a analisar.
