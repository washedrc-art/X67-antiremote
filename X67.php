<?php
declare(strict_types=1);

const REPORT_FILE = '/sdcard/Download/x67_scanner_report.html';

$script = __DIR__ . '/x67_antiremote.py';
if (!is_file($script)) {
    fwrite(STDERR, "x67_antiremote.py não encontrado.\n");
    exit(1);
}

@mkdir(dirname(REPORT_FILE), 0777, true);

$cmd = 'python3 ' . escapeshellarg($script) . ' 2>&1';
$output = shell_exec($cmd) ?? '';

function esc(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$html = '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
      . '<meta name="viewport" content="width=device-width,initial-scale=1">'
      . '<title>X67 AntiRemote — Relatório</title><style>'
      . 'body{margin:0;background:#0f0b16;color:#fff;font:15px monospace}'
      . '.wrap{max-width:1050px;margin:30px auto;padding:0 16px}'
      . '.card{border:1px solid #a66cff;border-radius:20px;padding:24px;background:#1a1125}'
      . '.title{text-align:center;font:800 32px sans-serif;letter-spacing:4px}'
      . 'pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #50386b;border-radius:14px;padding:18px;background:#09070d}'
      . '</style></head><body><div class="wrap"><div class="card">'
      . '<h1 class="title">X67 ANTIREMOTE</h1>'
      . '<pre>' . esc($output) . '</pre>'
      . '</div></div></body></html>';

file_put_contents(REPORT_FILE, $html);
echo "\nRelatório HTML: " . REPORT_FILE . "\n";
