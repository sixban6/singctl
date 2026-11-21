// Package lifecycle 提供与 sing-box 一致的三阶段确定性服务生命周期编排（StageInit -> StageStart -> StagePostStart）
// 与严格逆序资源回收能力。
package lifecycle

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const defaultCloseTimeout = 5 * time.Second

// Stage 定义生命周期编排的三个确定性阶段。
type Stage int

const (
	// StageInit 初始化阶段：加载配置、打开持久化文件与准备锁资源。
	StageInit Stage = iota
	// StageStart 启动阶段：拉起后台协程、监听器与守护轮询。
	StageStart
	// StagePostStart 就绪后阶段：触发预热与非阻塞后台首轮同步。
	StagePostStart
)

// String 返回阶段的可读名称。
func (s Stage) String() string {
	switch s {
	case StageInit:
		return "init"
	case StageStart:
		return "start"
	case StagePostStart:
		return "post_start"
	default:
		return "unknown"
	}
}

var (
	// ErrAlreadyStarted 表示生命周期编排组已启动，禁止重复启动。
	ErrAlreadyStarted = errors.New("lifecycle group already started")
	// ErrGroupClosed 表示生命周期编排组已关闭，禁止再次启动。
	ErrGroupClosed = errors.New("lifecycle group already closed")
)

var startStages = [...]Stage{
	StageInit,
	StageStart,
	StagePostStart,
}

// Service 定义受生命周期编排器托管的服务契约。
type Service interface {
	Name() string
	Start(ctx context.Context, stage Stage) error
	Close() error
}

// FuncService 为轻量回调提供的适配器，避免每次定义模板结构体。
type FuncService struct {
	ServiceName string
	OnInit      func(ctx context.Context) error
	OnStart     func(ctx context.Context) error
	OnPostStart func(ctx context.Context) error
	OnClose     func() error
}

// Name 返回服务名称，未设置时默认返回 "anonymous"。
func (f FuncService) Name() string {
	return cmp.Or(strings.TrimSpace(f.ServiceName), "anonymous")
}

// Start 按阶段分发到对应的回调函数。
func (f FuncService) Start(ctx context.Context, stage Stage) error {
	switch stage {
	case StageInit:
		if f.OnInit != nil {
			return f.OnInit(ctx)
		}
	case StageStart:
		if f.OnStart != nil {
			return f.OnStart(ctx)
		}
	case StagePostStart:
		if f.OnPostStart != nil {
			return f.OnPostStart(ctx)
		}
	}
	return nil
}

// Close 执行清理回调。
func (f FuncService) Close() error {
	if f.OnClose != nil {
		return f.OnClose()
	}
	return nil
}

// GroupOption 定义生命周期编排组的配置项。
type GroupOption func(*Group)

// WithCloseTimeout 设置单个服务在 Close() 时的最大等待超时时间。
func WithCloseTimeout(d time.Duration) GroupOption {
	return func(g *Group) {
		if d > 0 {
			g.closeTimeout = d
		}
	}
}

// Group 负责按确定性顺序三阶段启动服务，并在失败或关闭时严格逆序回收资源。
type Group struct {
	mu           sync.Mutex
	closeMu      sync.Mutex
	closeTimeout time.Duration
	services     []Service
	touched      []bool
	started      bool
	closed       bool
	closeDone    bool
	closeErr     error
}

// NewGroup 创建一个新的生命周期编排组。
func NewGroup(opts ...GroupOption) *Group {
	g := &Group{
		closeTimeout: defaultCloseTimeout,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}
	return g
}

// Add 注册一个或多个受托管服务，自动忽略 nil 项。
func (g *Group) Add(services ...Service) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started || g.closed {
		return
	}
	for _, svc := range services {
		if svc != nil {
			g.services = append(g.services, svc)
			g.touched = append(g.touched, false)
		}
	}
}

// Start 依序执行 StageInit -> StageStart -> StagePostStart，任何阶段失败将自动逆序回滚已触达的服务。
func (g *Group) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrGroupClosed
	}
	if g.started {
		g.mu.Unlock()
		return ErrAlreadyStarted
	}
	g.started = true
	services := append([]Service(nil), g.services...)
	g.mu.Unlock()

	for _, stage := range startStages {
		for idx, svc := range services {
			if err := ctx.Err(); err != nil {
				rollbackErr := g.closeInternal()
				return errors.Join(fmt.Errorf("lifecycle %s [%s]: %w", stage, serviceName(svc), err), rollbackErr)
			}
			if err := svc.Start(ctx, stage); err != nil {
				rollbackErr := g.closeInternal()
				return errors.Join(fmt.Errorf("lifecycle %s [%s]: %w", stage, serviceName(svc), err), rollbackErr)
			}
			g.mu.Lock()
			g.touched[idx] = true
			g.mu.Unlock()
		}
	}
	return nil
}

// Close 幂等且严格逆序地关闭所有已触达的服务，并受单服务超时约束。
func (g *Group) Close() error {
	return g.closeInternal()
}

func (g *Group) closeInternal() error {
	g.closeMu.Lock()
	defer g.closeMu.Unlock()

	g.mu.Lock()
	if g.closeDone {
		err := g.closeErr
		g.mu.Unlock()
		return err
	}
	g.closed = true
	services := append([]Service(nil), g.services...)
	touched := append([]bool(nil), g.touched...)
	timeout := g.closeTimeout
	g.mu.Unlock()

	var errs []error
	for i := len(services) - 1; i >= 0; i-- {
		if !touched[i] {
			continue
		}
		if err := closeServiceBounded(services[i], timeout); err != nil {
			errs = append(errs, err)
		}
	}

	err := errors.Join(errs...)
	g.mu.Lock()
	g.closeErr = err
	g.closeDone = true
	g.mu.Unlock()
	return err
}

func closeServiceBounded(svc Service, timeout time.Duration) error {
	if svc == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultCloseTimeout
	}

	done := make(chan error, 1)
	go func() {
		done <- svc.Close()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("lifecycle close [%s]: %w", serviceName(svc), err)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("lifecycle close [%s]: %w", serviceName(svc), context.DeadlineExceeded)
	}
}

func serviceName(svc Service) string {
	if svc == nil {
		return "nil"
	}
	return cmp.Or(strings.TrimSpace(svc.Name()), "anonymous")
}
