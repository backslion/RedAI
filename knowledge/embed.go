// embed.go：OpenAI 兼容的 embeddings 客户端。
//
// 兼容面：任何暴露 POST {base}/embeddings 的服务（OpenAI、智谱、SiliconFlow、
// Ollama、vLLM、new-api 等）都能用，只认 {model, input} 与 {data:[{index,embedding}]}。
// 不做重试与并发：入库是一次性动作，失败就让调用方降级为纯关键词，别把一次
// 向量化失败放大成整篇文档入库失败。

package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// embedBatchSize 是单次请求的最大文本数（各家上限 16～2048，取 16 最稳）。
const embedBatchSize = 16

// embedTimeout 是单次 embeddings 请求的墙钟上限。
const embedTimeout = 90 * time.Second

type embedRequest struct {
	Model      string   `json:"model"`
	Input      []string `json:"input"`
	Dimensions int      `json:"dimensions,omitempty"`
}

type embedResponse struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// EmbedBatch 把一批文本向量化，返回顺序与输入一致。
func (c Config) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if !c.Ready() {
		return nil, fmt.Errorf("向量模型未配置")
	}
	if len(texts) == 0 {
		return nil, nil
	}
	out := make([][]float32, len(texts))
	for start := 0; start < len(texts); start += embedBatchSize {
		end := start + embedBatchSize
		if end > len(texts) {
			end = len(texts)
		}
		vecs, err := c.embedOnce(ctx, texts[start:end])
		if err != nil {
			return nil, err
		}
		for i := range vecs {
			if start+i < len(out) {
				out[start+i] = vecs[i]
			}
		}
	}
	return out, nil
}

func (c Config) embedOnce(ctx context.Context, batch []string) ([][]float32, error) {
	// 清空正文里的空串：部分服务对空 input 直接 400。
	inputs := make([]string, len(batch))
	for i, t := range batch {
		t = strings.TrimSpace(t)
		if t == "" {
			t = "（空段落）"
		}
		if len([]rune(t)) > 8000 {
			t = string([]rune(t)[:8000])
		}
		inputs[i] = t
	}
	body, err := json.Marshal(embedRequest{Model: c.Model, Input: inputs, Dimensions: c.Dim})
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/") + "/embeddings"
	ctx, cancel := context.WithTimeout(ctx, embedTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.APIKey))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embeddings 返回 %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	var parsed embedResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("embeddings 响应无法解析: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return nil, fmt.Errorf("embeddings 报错: %s", parsed.Error.Message)
	}
	if len(parsed.Data) != len(batch) {
		return nil, fmt.Errorf("embeddings 返回条数不符: 期望 %d 实得 %d", len(batch), len(parsed.Data))
	}
	out := make([][]float32, len(batch))
	for _, d := range parsed.Data {
		if d.Index < 0 || d.Index >= len(out) {
			continue
		}
		out[d.Index] = d.Embedding
	}
	for i, v := range out {
		if len(v) == 0 {
			return nil, fmt.Errorf("embeddings 第 %d 条为空", i)
		}
	}
	return out, nil
}

// Cosine 计算余弦相似度（两边维度不一致时按较短的一边算，避免脏数据直接报错）。
func Cosine(a, b []float32) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := 0; i < n; i++ {
		x, y := float64(a[i]), float64(b[i])
		dot += x * y
		na += x * x
		nb += y * y
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
