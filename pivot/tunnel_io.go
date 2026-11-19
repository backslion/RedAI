package pivot

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// socksAuth 是隧道入口的可选认证（RFC 1929）。
type socksAuth struct {
	user string
	pass string
}

// socks5 服务端：只实现 CONNECT。
//
// 为什么不实现 BIND / UDP ASSOCIATE：
//   - BIND 是给 FTP 主动模式这类「服务端反向连客户端」用的，横向场景极少，
//     而且要在目标侧再开监听，暴露面远大于收益。
//   - UDP ASSOCIATE 只能走 SOCKS5 的 UDP 转发，SSH 的 direct-tcpip 通道是纯 TCP，
//     实现不了；假装支持只会让 DNS 走 UDP 的工具静默失效。
//
// 明确拒绝（返回 0x07 Command not supported）比静默超时好：调用方能立刻知道
// 是「协议不支持」而不是「网络不通」，不会白排查半小时。

// rep 是 SOCKS5 应答码。
const (
	repOK            = 0x00
	repFail          = 0x01
	repNotAllowed    = 0x02
	repHostUnreach   = 0x04
	repConnRefused   = 0x05
	repCmdNotSupport = 0x07
	repAddrNotSupp   = 0x08
)

// serveSocksConn 处理一个 SOCKS5 客户端。
func (t *Tunnel) serveSocksConn(c net.Conn) {
	defer c.Close()
	t.activeNow.Add(1)
	defer t.activeNow.Add(-1)

	_ = c.SetDeadline(time.Now().Add(socksHandshakeTimeout))
	target, err := t.socksHandshake(c)
	if err != nil {
		t.fails.Add(1)
		t.recordConn(connLog{At: time.Now(), OK: false, Err: err.Error()})
		return
	}
	_ = c.SetDeadline(time.Time{})

	up, err := t.dialVia(target)
	if err != nil {
		t.fails.Add(1)
		t.recordConn(connLog{At: time.Now(), Target: target, OK: false, Err: err.Error()})
		_ = writeSocksReply(c, repHostUnreach, nil)
		return
	}
	defer up.Close()

	// 应答里的 BND.ADDR 在代理场景没有意义（客户端也不会用），填 0.0.0.0:0。
	if err := writeSocksReply(c, repOK, nil); err != nil {
		t.fails.Add(1)
		return
	}

	nUp, nDown := pipeBoth(c, up)
	t.conns.Add(1)
	t.up.Add(nUp)
	t.down.Add(nDown)
	t.recordConn(connLog{At: time.Now(), Target: target, OK: true, Up: nUp, Down: nDown})
}

// serveForwardConn 处理一个端口转发客户端：目标固定，不需要协商。
func (t *Tunnel) serveForwardConn(c net.Conn) {
	defer c.Close()
	t.activeNow.Add(1)
	defer t.activeNow.Add(-1)

	up, err := t.dialVia(t.Target)
	if err != nil {
		t.fails.Add(1)
		t.recordConn(connLog{At: time.Now(), Target: t.Target, OK: false, Err: err.Error()})
		return
	}
	defer up.Close()

	nUp, nDown := pipeBoth(c, up)
	t.conns.Add(1)
	t.up.Add(nUp)
	t.down.Add(nDown)
	t.recordConn(connLog{At: time.Now(), Target: t.Target, OK: true, Up: nUp, Down: nDown})
}

// socksHandshake 完成协商并返回目标 host:port。
func (t *Tunnel) socksHandshake(c net.Conn) (string, error) {
	// ── 阶段 1：方法协商 ──
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", fmt.Errorf("读握手失败: %w", err)
	}
	if head[0] != 0x05 {
		return "", fmt.Errorf("非 SOCKS5 客户端（VER=0x%02x）", head[0])
	}
	n := int(head[1])
	if n == 0 {
		return "", fmt.Errorf("客户端未提供任何认证方法")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", fmt.Errorf("读认证方法失败: %w", err)
	}

	want := byte(0x00)
	if t.auth != nil {
		want = 0x02
	}
	if !containsByte(methods, want) {
		_, _ = c.Write([]byte{0x05, 0xff})
		return "", fmt.Errorf("客户端不支持所需认证方式（本隧道要求 0x%02x）", want)
	}
	if _, err := c.Write([]byte{0x05, want}); err != nil {
		return "", err
	}

	// ── 阶段 2：认证 ──
	if t.auth != nil {
		var v [2]byte
		if _, err := io.ReadFull(c, v[:]); err != nil {
			return "", fmt.Errorf("读认证报文失败: %w", err)
		}
		if v[0] != 0x01 {
			_, _ = c.Write([]byte{0x01, 0x01})
			return "", fmt.Errorf("不支持的认证子协议版本 %d", v[0])
		}
		user := make([]byte, int(v[1]))
		if _, err := io.ReadFull(c, user); err != nil {
			return "", err
		}
		var pl [1]byte
		if _, err := io.ReadFull(c, pl[:]); err != nil {
			return "", err
		}
		pass := make([]byte, int(pl[0]))
		if _, err := io.ReadFull(c, pass); err != nil {
			return "", err
		}
		if string(user) != t.auth.user || string(pass) != t.auth.pass {
			_, _ = c.Write([]byte{0x01, 0x01})
			return "", fmt.Errorf("SOCKS5 认证失败")
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return "", err
		}
	}

	// ── 阶段 3：请求 ──
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", fmt.Errorf("读请求失败: %w", err)
	}
	if req[0] != 0x05 {
		return "", fmt.Errorf("请求版本非法 0x%02x", req[0])
	}
	if req[1] != 0x01 {
		_ = writeSocksReply(c, repCmdNotSupport, nil)
		return "", fmt.Errorf("只支持 CONNECT（请求命令 0x%02x）", req[1])
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	case 0x03: // 域名
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", err
		}
		if l[0] == 0 {
			return "", fmt.Errorf("目标域名为空")
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = string(b)
	case 0x04: // IPv6
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		host = net.IP(b[:]).String()
	default:
		_ = writeSocksReply(c, repAddrNotSupp, nil)
		return "", fmt.Errorf("不支持的地址类型 0x%02x", req[3])
	}

	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(pb[:])
	if port == 0 {
		return "", fmt.Errorf("目标端口为 0")
	}
	// 防自环：客户端把代理自己当目标会打出一个无限循环。
	if strings.EqualFold(host, "127.0.0.1") || strings.EqualFold(host, "localhost") || strings.EqualFold(host, "::1") {
		if fmt.Sprintf("%d", port) == portOf(t.Listen) {
			_ = writeSocksReply(c, repNotAllowed, nil)
			return "", fmt.Errorf("拒绝把隧道自身作为目标（自环）")
		}
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// writeSocksReply 写应答。bnd 为空时填 0.0.0.0:0。
func writeSocksReply(w io.Writer, rep byte, bnd net.Addr) error {
	out := []byte{0x05, rep, 0x00}
	if bnd != nil {
		if ta, ok := bnd.(*net.TCPAddr); ok && ta.IP.To4() != nil {
			out = append(out, 0x01)
			out = append(out, ta.IP.To4()...)
			var p [2]byte
			binary.BigEndian.PutUint16(p[:], uint16(ta.Port))
			out = append(out, p[:]...)
			_, err := w.Write(out)
			return err
		}
	}
	out = append(out, 0x01, 0, 0, 0, 0, 0, 0)
	_, err := w.Write(out)
	return err
}

// pipeBoth 双向搬数据并返回 (客户端→目标, 目标→客户端) 字节数。
// 任一侧 EOF 即半关另一侧的写方向（TCP 语义），但对端可能还在吐数据，
// 所以等两个方向都结束才返回。
func pipeBoth(a, b net.Conn) (int64, int64) {
	var wg sync.WaitGroup
	var up, down int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(b, a)
		up = n
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(a, b)
		down = n
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
	return up, down
}

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

// portOf 取 "host:port" 的端口字符串。
func portOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return p
}
