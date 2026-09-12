<?php

declare(strict_types=1);

const REPORT_DIR = '/sdcard/download';
const REPORT_FILE = '/sdcard/download/x67_scanner_report.html';

function esc(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function c(string $s): string { return "\e[" . $s . "m"; }

function banner(): void {
    echo c('97;1') . "\n  ╔══════════════════════════════════════════════════════════════╗\n";
    echo "  ║                         X67 SCANNER                         ║\n";
    echo "  ╚══════════════════════════════════════════════════════════════╝\n" . "\e[0m";
    echo c('97') . "  Relatório HTML: /sdcard/download/x67_scanner_report.html\n\e[0m\n";
}

function writeReport(string $output, int $code, float $started): void {
    if (!is_dir(REPORT_DIR)) {
        @mkdir(REPORT_DIR, 0777, true);
    }
    $when = date('Y-m-d H:i:s');
    $status = $code === 0 ? 'Concluída' : 'Finalizada com código ' . $code;
    $html = '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>X67 Scanner — Relatório</title><style>'
        . 'body{margin:0;background:#120b1d;color:#fff;font:15px monospace} '
        . '.wrap{max-width:1000px;margin:30px auto;padding:0 18px} '
        . '.card{border:1px solid #9b5cff;border-radius:18px;padding:24px;background:#1b1029;box-shadow:0 0 28px #6d35aa55} '
        .title{text-align:center;font-size:34px;font-weight:800;letter-spacing:4px;margin:0 0 8px} '
        .sub{text-align:center;color:#ddd;margin-bottom:24px}.meta{color:#d8bfff;margin-bottom:18px} '
        'pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #5e397d;border-radius:12px;padding:18px;background:#0c0712;color:#fff;line-height:1.45} '
        '.ok{color:#d8bfff}.foot{margin-top:16px;color:#aaa;font-size:12px}'
        . '</style></head><body><div class="wrap"><div class="card">'
        . '<h1 class="title">X67 SCANNER</h1><div class="sub">Relatório da análise</div>'
        . '<div class="meta">Data: ' . esc($when) . '<br>Status: ' . esc($status) . '</div>'
        . '<pre>' . esc($output) . '</pre>'
        . '<div class="foot">Arquivo: /sdcard/download/x67_scanner_report.html</div>'
        . '</div></div></body></html>';
    @file_put_contents(REPORT_FILE, $html);
}

banner();
$bin = __DIR__ . '/X67';
if (!is_file($bin)) { fwrite(STDERR, "X67 não encontrado.\n"); exit(1); }
@chmod($bin, 0755);
$started = microtime(true);
$cmd = '"' . $bin . '" 2>&1';
$output = shell_exec($cmd) ?? '';
$code = 0;
writeReport($output, $code, $started);
echo c('97;1') . "\n  Relatório salvo em: /sdcard/download/x67_scanner_report.html\n\e[0m";
