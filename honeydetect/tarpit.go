package honeydetect

// Tarpit：对已判定为蜜罐的目标做「减速 → 熔断」。
//
// 为什么需要：AI 攻击代理最大的风险不是打不进去，而是**在仿真环境里打得兴起**。
// 一旦 honeypot_check 判定某目标可信度较高，继续高频请求只会给防守方喂更多
// 行为样本（键盘节奏、工具链特征、payload 习惯），还可能触发反制。
//
// 策略（三档，不做一刀切）：
//   - 前 3 次：完全放行。honeypot_check 误报率不低（自定义运维平台、老旧设备
//     都可能命中签名），一刀切断会让 agent 失去验证机会。
//   - 4~8 次：指数退避（1s/2s/4s/8s）。既能继续取证，又把请求速率压到
//     「人类手动操作」的量级。
//   - 超过 8 次：熔断，直接拒绝并给出明确理由，逼 agent 换目标或写 fact 收尾。
//
// 为什么用「次数」而不是「速率」：速率需要时间窗和后台清理，且对慢速渗透
// （每条请求间隔几十秒）完全不起作用。次数直接对应「在这个目标上已经做了
// 多少动作」，与风险线性相关。
//
// 状态只在内存里：进程重启后清空。这是有意的——重启后重新判断一次蜜罐，
// 比带着一个可能已经过期的黑名单更安全。

import (
	"sync"
	"time"
)

const (
	// tarpitFreeHits 是判定可疑后仍完全放行的次数。
	tarpitFreeHits = 3
	// tarpitMaxHits 是熔断阈值。
	tarpitMaxHits = 8
	// tarpitIdleTTL 是目标的空闲过期时间：超过这么久没访问就忘掉它。
	// 不清理会让 map 随任务数量无界增长。
	tarpitIdleTTL = 30 * time.Minute
	// tarpitMaxDelay 是单次退避上限。
	tarpitMaxDelay = 8 * time.Second
)

// TarpitVerdict 是一次访问裁决。
type TarpitVerdict struct {
	// Delay 是本次请求前应等待的时长。0 表示无需等待。
	Delay time.Duration `json:"delay_ms"`
	// Blocked 为 true 时调用方必须放弃本次请求。
	Blocked bool `json:"blocked"`
	// Reason 是可读理由（会进工具返回值，供模型判断下一步）。
	Reason string `json:"reason,omitempty"`
	// Hits 是该目标累计被访问次数（含本次）。
	Hits int `json:"hits"`
	// Score 是判定蜜罐时的置信度。
	Score float64 `json:"score,omitempty"`
}

type tarpitState struct {
	hits  int
	last  time.Time
	score float64
}

// Tarpit 是按目标维护的访问计数器。
type Tarpit struct {
	mu      sync.Mutex
	targets map[string]*tarpitState
	// now 可在测试里替换，避免真的 sleep。
	now func() time.Time
}

// NewTarpit 构造一个空表。
func NewTarpit() *Tarpit {
	return &Tarpit{targets: map[string]*tarpitState{}, now: time.Now}
}

var (
	defaultOnce   sync.Once
	defaultTarpit *Tarpit
)

// DefaultTarpit 返回进程默认实例。
//
// 允许包级单例的理由：它只是一张内存计数表，没有需要 Close 的资源、没有后台
// goroutine，与 listener/pivot 那些持有端口与连接的管理器不同。仍可由
// agent.Runtime.Tarpit 显式覆盖（多实例/单测隔离）。
func DefaultTarpit() *Tarpit {
	defaultOnce.Do(func() { defaultTarpit = NewTarpit() })
	return defaultTarpit
}

// MarkSuspect 登记一个可疑目标。score 是 honeypot_check 的置信度。
func (t *Tarpit) MarkSuspect(host string, score float64) {
	if host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.targets[host]
	if !ok {
		s = &tarpitState{}
		t.targets[host] = s
	}
	if score > s.score {
		s.score = score
	}
	s.last = t.now()
}

// Gate 在每次访问前调用，返回是否需要延迟或熔断，并累计访问次数。
func (t *Tarpit) Gate(host string) TarpitVerdict {
	if host == "" {
		return TarpitVerdict{}
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	t.gcLocked(now)

	s, ok := t.targets[host]
	if !ok {
		return TarpitVerdict{}
	}
	s.hits++
	s.last = now

	switch {
	case s.hits <= tarpitFreeHits:
		return TarpitVerdict{Hits: s.hits, Score: s.score}
	case s.hits > tarpitMaxHits:
		return TarpitVerdict{
			Blocked: true,
			Hits:    s.hits,
			Score:   s.score,
			Reason: "该目标已被判定为疑似蜜罐，且已累计访问 " + itoa(s.hits) +
				" 次，熔断以停止继续喂样本。请换目标，或把结论写成 fact 后收尾。",
		}
	}
	// 4~8 次：1s/2s/4s/8s。
	delay := time.Second << (s.hits - tarpitFreeHits - 1)
	if delay > tarpitMaxDelay {
		delay = tarpitMaxDelay
	}
	return TarpitVerdict{
		Delay: delay,
		Hits:  s.hits,
		Score: s.score,
		Reason: "该目标被判定为疑似蜜罐，已访问 " + itoa(s.hits) +
			" 次，本次减速 " + delay.String() + " 以降低行为样本密度。",
	}
}

// Clear 手动解除某目标的标记（人工确认误报后）。
func (t *Tarpit) Clear(host string) {
	t.mu.Lock()
	delete(t.targets, host)
	t.mu.Unlock()
}

// Snapshot 返回当前被标记的目标（供接口/排查）。
func (t *Tarpit) Snapshot() map[string]TarpitVerdict {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]TarpitVerdict, len(t.targets))
	for h, s := range t.targets {
		out[h] = TarpitVerdict{Hits: s.hits, Score: s.score}
	}
	return out
}

// gcLocked 清理空闲过久的目标。调用方必须持锁。
func (t *Tarpit) gcLocked(now time.Time) {
	for h, s := range t.targets {
		if now.Sub(s.last) > tarpitIdleTTL {
			delete(t.targets, h)
		}
	}
}

// itoa 避免为了一个数字引入 strconv 的 import 噪音（与包内已有风格一致）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
