# X67 AntiRemote

Scanner de integridade/forense para análise autorizada de Free Fire em Android usando Termux + ADB.

## Requisitos

- Termux atualizado
- Python 3
- Android Debug Bridge (ADB)
- Depuração USB/Wireless Debugging autorizada
- Acesso permitido ao armazenamento quando necessário

## Instalação rápida

```bash
pkg update -y && pkg upgrade -y
pkg install -y python android-tools git
termux-setup-storage
git clone https://github.com/SEU_USUARIO/X67-AntiRemote.git
cd X67-AntiRemote
python -m pip install --upgrade pip
pip install -r requirements.txt
chmod +x install.sh x67_antiremote.py
python x67_antiremote.py
```

## ADB via localhost

Antes de iniciar o scanner, conecte o ADB. Exemplo para ADB over Wi-Fi:

```bash
adb connect 127.0.0.1:PORTA
adb devices
```

Use a porta exibida pelo método de depuração sem fio/ADB do aparelho. O resultado precisa mostrar `device`, não `unauthorized` ou `offline`.

## Atualizar o scanner

Dentro da pasta do projeto:

```bash
cd ~/X67-AntiRemote
git pull --ff-only
python -m pip install --upgrade pip
pip install -r requirements.txt --upgrade
python x67_antiremote.py
```

## O que ele coleta

- versão/API/modelo do Android;
- informações do pacote via Package Manager;
- caminhos do APK;
- cópia do APK quando o ADB permite;
- SHA-256 do APK;
- arquivos em Android/data e Android/obb acessíveis;
- arquivos de código/libs (`.so`, `.dex`, `.odex`, `.vdex`, `.apk`, `.jar`);
- arquivos com timestamp nas últimas 24 horas;
- comparação com baseline;
- Logcat disponível no momento da coleta;
- processos/PID;
- dumpsys meminfo;
- `/proc/PID/maps` quando permitido;
- sockets e informações de rede disponíveis;
- IPs encontrados nas fontes coletadas.

## Importante sobre "últimas 24h"

Timestamps só mostram alteração dentro das últimas 24 horas quando o Android ainda possui o timestamp correspondente. Para detectar alterações comparando estado anterior, o scanner cria um **baseline**. A primeira execução cria esse baseline; execuções posteriores conseguem apontar arquivos adicionados, removidos ou modificados.

## Importante sobre logs e IPs

O scanner não apaga logs nem tenta reconstruir dados que já foram sobrescritos. Logcat e algumas estatísticas de rede são rotativas/limitadas. Um IP não é considerado prova de cheat por si só.

## Classificação

- `LIMPO`: nenhuma evidência detectável pelas fontes coletadas.
- `REVISÃO`: existem indicadores que precisam de análise humana.
- `W.O`: alteração de arquivos detectada em relação ao baseline.

O resultado é deliberadamente conservador para reduzir falsos positivos.

## Relatórios

Os relatórios ficam em:

```text
~/x67_antiremote/reports/
```

Baselines:

```text
~/x67_antiremote/baselines/
```

Cada análise cria uma pasta com:

- `report.json`
- `SUMMARY.txt`
- `logcat_full.txt`
- `logcat_indicators.txt`
- `game_files.json`
- `processes.txt`
- `meminfo.txt`
- `maps.txt` (quando disponível)
- `network_*.txt`
- `ips_found.txt`
- APKs coletados, quando permitido

## Uso responsável

Use somente em aparelhos/jogadores que você está autorizado a analisar e respeite as regras do jogo, da plataforma e as leis aplicáveis.
