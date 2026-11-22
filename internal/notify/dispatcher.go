// 文件职责：实现支持热更新、有界异步队列、受控生命周期与近期环形历史的告警推送调度器。
package notify

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/logger"
)

// Dispatcher 负责统一执行防刷屏策略、有界异步队列投递、同步测试推送与历史记录维护。
type Dispatcher struct {
	httpClient  *http.Client
	nowFn       func() time.Time
	hostname    string
	sendTimeout time.Duration
	logf        func(format string, args ...any)

	mu          sync.Mutex
	opts        Options
	quietWindow QuietWindow
	channels    []Channel
	policy      policyState
	queue       []Event
	notifyCh    chan struct{}
	history     []HistoryRecord
	started     bool
	closed      bool
	cancel      context.CancelFunc
	done        chan struct{}
}

// NewDispatcher 创建带显式依赖注入的通知调度器。
func NewDispatcher(opts Options, deps DispatcherDeps) *Dispatcher {
	nowFn := deps.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}
	logf := deps.Logf
	if logf == nil {
		logf = logger.Warn
	}
	hostname := strings.TrimSpace(deps.Hostname)
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}
	sendTimeout := deps.SendTimeout
	if sendTimeout <= 0 {
		sendTimeout = DefaultSendTimeout
	}

	d := &Dispatcher{
		httpClient:  resolveHTTPClient(deps.HTTPClient),
		nowFn:       nowFn,
		hostname:    hostname,
		sendTimeout: sendTimeout,
		logf:        logf,
		policy:      newPolicyState(),
		queue:       make([]Event, 0, MaxQueueSize),
		notifyCh:    make(chan struct{}, 1),
		history:     make([]HistoryRecord, 0, MaxHistorySize),
	}
	d.UpdateOptions(opts)
	return d
}

// UpdateOptions 并发安全地热更新调度器配置与渠道实例。
func (d *Dispatcher) UpdateOptions(opts Options) {
	cloned := opts.Clone()
	quiet, err := ParseQuietHours(cloned.QuietHours)
	if err != nil {
		d.logf("notify: ignore invalid quiet_hours %q: %v", cloned.QuietHours, err)
		quiet = QuietWindow{}
	}
	channels := BuildChannels(cloned)

	d.mu.Lock()
	d.opts = cloned
	d.quietWindow = quiet
	d.channels = channels
	d.mu.Unlock()
}

// Start 启动受 ctx 控制的单个后台投递消费协程（幂等，防止重复启动）。
func (d *Dispatcher) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	d.mu.Lock()
	if d.started || d.closed {
		d.mu.Unlock()
		return
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	d.started = true
	d.cancel = cancel
	d.done = done
	hasPending := len(d.queue) > 0
	d.mu.Unlock()

	if hasPending {
		d.signalWorker()
	}
	go d.runWorker(workerCtx, done)
}

// Close 取消后台协程并等待在途投递安全结束（幂等）。
func (d *Dispatcher) Close() {
	d.mu.Lock()
	d.closed = true
	cancel := d.cancel
	done := d.done
	d.cancel = nil
	d.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// Emit 执行策略校验并将通过的事件非阻塞投入异步队列；队列满时丢弃最旧事件并记录日志。
func (d *Dispatcher) Emit(ev Event) (queued bool, reason string) {
	now := d.nowFn()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = now
	}
	if strings.TrimSpace(ev.Hostname) == "" {
		ev.Hostname = d.hostname
	}
	ev.Severity = cmp.Or(ev.Severity, SeverityInfo)

	var droppedTitle string
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return false, "closed"
	}
	ok, rejectReason := d.policy.evaluateAndRecord(d.opts, d.quietWindow, len(d.channels) > 0, ev, now)
	if !ok {
		d.mu.Unlock()
		return false, rejectReason
	}
	if len(d.queue) >= MaxQueueSize {
		droppedTitle = cmp.Or(d.queue[0].Title, string(d.queue[0].Type))
		copy(d.queue, d.queue[1:])
		d.queue[len(d.queue)-1] = ev
	} else {
		d.queue = append(d.queue, ev)
	}
	d.mu.Unlock()

	if droppedTitle != "" {
		d.logf("notify: queue full (%d), dropped oldest event %q", MaxQueueSize, droppedTitle)
	}
	d.signalWorker()
	return true, ""
}

// SendTest 同步向指定渠道或全部已启用渠道发送测试消息（不占每日限额、不受静默窗限制）。
func (d *Dispatcher) SendTest(ctx context.Context, opts Options, targetChannel string) []DeliveryResult {
	if ctx == nil {
		ctx = context.Background()
	}
	ev := Event{
		Type:      EventTest,
		Severity:  SeverityInfo,
		DedupKey:  "test",
		Hostname:  d.hostname,
		Title:     "SingCtl 通知测试",
		Body:      "这是一条来自 SingCtl 的测试通知，用于验证推送渠道连通性。",
		Resolved:  false,
		Timestamp: d.nowFn(),
	}

	target := strings.ToLower(strings.TrimSpace(targetChannel))
	if target != "" {
		factory, found := lookupChannelFactory(target)
		if !found {
			return []DeliveryResult{{
				Channel: target,
				OK:      false,
				Error:   fmt.Sprintf("unknown channel %q", target),
			}}
		}
		if !factory.configured(opts) {
			return []DeliveryResult{{
				Channel: factory.name,
				OK:      false,
				Error:   fmt.Sprintf("channel %q is not enabled", factory.name),
			}}
		}
		results := d.deliverToChannels(ctx, []Channel{factory.build(opts)}, ev)
		d.recordHistory(ev, results)
		return results
	}

	channels := make([]Channel, 0, len(channelFactories))
	for _, factory := range channelFactories {
		if factory.configured(opts) {
			channels = append(channels, factory.build(opts))
		}
	}
	if len(channels) == 0 {
		return []DeliveryResult{}
	}
	results := d.deliverToChannels(ctx, channels, ev)
	d.recordHistory(ev, results)
	return results
}

// RecentHistory 返回近期推送历史记录的防御性深拷贝（最多 50 条，最新在前）。
func (d *Dispatcher) RecentHistory() []HistoryRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]HistoryRecord, len(d.history))
	for i, rec := range d.history {
		rec.Channels = slices.Clone(rec.Channels)
		out[i] = rec
	}
	return out
}

func (d *Dispatcher) signalWorker() {
	select {
	case d.notifyCh <- struct{}{}:
	default:
	}
}

func (d *Dispatcher) runWorker(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		for ctx.Err() == nil {
			ev, channels, ok := d.popNext()
			if !ok {
				break
			}
			if len(channels) == 0 {
				continue
			}
			results := d.deliverToChannels(ctx, channels, ev)
			d.recordHistory(ev, results)
		}
		select {
		case <-ctx.Done():
			return
		case <-d.notifyCh:
		}
	}
}

func (d *Dispatcher) popNext() (Event, []Channel, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queue) == 0 {
		return Event{}, nil, false
	}
	ev := d.queue[0]
	copy(d.queue, d.queue[1:])
	d.queue[len(d.queue)-1] = Event{}
	d.queue = d.queue[:len(d.queue)-1]
	channels := slices.Clone(d.channels)
	return ev, channels, true
}

func (d *Dispatcher) deliverToChannels(ctx context.Context, channels []Channel, ev Event) []DeliveryResult {
	results := make([]DeliveryResult, len(channels))
	var wg sync.WaitGroup
	for i, ch := range channels {
		wg.Go(func() {
			start := time.Now()
			sendCtx, cancel := context.WithTimeout(ctx, d.sendTimeout)
			defer cancel()

			err := ch.Send(sendCtx, d.httpClient, ev)
			res := DeliveryResult{
				Channel:   ch.Name(),
				OK:        err == nil,
				LatencyMs: time.Since(start).Milliseconds(),
			}
			if err != nil {
				res.Error = err.Error()
			}
			results[i] = res
		})
	}
	wg.Wait()
	return results
}

func (d *Dispatcher) recordHistory(ev Event, results []DeliveryResult) {
	if len(results) == 0 {
		return
	}
	channels := make([]string, 0, len(results))
	var errs []string
	for _, r := range results {
		channels = append(channels, r.Channel)
		if !r.OK && r.Error != "" {
			errs = append(errs, fmt.Sprintf("%s: %s", r.Channel, r.Error))
		}
	}
	rec := HistoryRecord{
		Time:      d.nowFn().Format(time.RFC3339),
		EventType: ev.Type,
		Severity:  ev.Severity,
		Title:     ev.Title,
		Channels:  channels,
		Success:   len(errs) == 0,
		Error:     strings.Join(errs, "; "),
	}

	d.mu.Lock()
	d.history = append([]HistoryRecord{rec}, d.history...)
	if len(d.history) > MaxHistorySize {
		d.history = d.history[:MaxHistorySize]
	}
	d.mu.Unlock()
}
