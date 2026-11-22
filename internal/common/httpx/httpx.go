// 文件职责：提供零反射 HTTP JSON Handler 泛型包装器、StatusError 状态码映射与防 OOM MaxBytesReader 安全解码。
package httpx

import (
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// DefaultMaxBodyBytes 为写接口 JSON 请求体的默认最大字节数（4 MiB），防止恶意超大载荷触发 OOM。
const DefaultMaxBodyBytes int64 = 4 << 20

// StatusError 携带显式 HTTP 状态码、对外安全提示文案与可选底层错误链。
type StatusError struct {
	Code    int
	Message string
	Err     error
}

func (e *StatusError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return http.StatusText(e.Code)
}

func (e *StatusError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// NewStatusError 创建带底层错误链的状态码错误。
func NewStatusError(code int, msg string, err error) *StatusError {
	return &StatusError{Code: code, Message: msg, Err: err}
}

func BadRequest(msg string) error   { return &StatusError{Code: http.StatusBadRequest, Message: msg} }
func Unauthorized(msg string) error { return &StatusError{Code: http.StatusUnauthorized, Message: msg} }
func Forbidden(msg string) error    { return &StatusError{Code: http.StatusForbidden, Message: msg} }
func NotFound(msg string) error     { return &StatusError{Code: http.StatusNotFound, Message: msg} }
func Conflict(msg string) error     { return &StatusError{Code: http.StatusConflict, Message: msg} }
func RateLimited(msg string) error {
	return &StatusError{Code: http.StatusTooManyRequests, Message: msg}
}
func BadGateway(msg string) error { return &StatusError{Code: http.StatusBadGateway, Message: msg} }
func Internal(msg string) error {
	return &StatusError{Code: http.StatusInternalServerError, Message: msg}
}

// WriteJSON 以标准 application/json 头部输出状态码与序列化 JSON 响应体。
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError 将 error 统一序列化为兼容前端契约的 `{"error": "..."}` JSON 响应。
func WriteError(w http.ResponseWriter, err error) {
	if err == nil {
		WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "unknown error"})
		return
	}
	if se, ok := errors.AsType[*StatusError](err); ok {
		code := se.Code
		if code < 100 || code > 599 {
			code = http.StatusInternalServerError
		}
		WriteJSON(w, code, map[string]string{"error": se.Error()})
		return
	}
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		WriteJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return
	}
	WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

// DecodeJSON 使用 http.MaxBytesReader 限制请求体尺寸并严格解码单个 JSON 对象（拒绝尾部多余垃圾数据）。
// 当 allowEmpty 为 true 时优雅容忍空请求体（返回 T 零值），但仍严格拒绝畸形 JSON。
func DecodeJSON[T any](w http.ResponseWriter, r *http.Request, maxBytes int64, allowEmpty bool) (T, error) {
	var zero T
	if r == nil || r.Body == nil {
		if allowEmpty {
			return zero, nil
		}
		return zero, BadRequest("empty request body")
	}

	limit := cmp.Or(maxBytes, DefaultMaxBodyBytes)
	r.Body = http.MaxBytesReader(w, r.Body, limit)

	dec := json.NewDecoder(r.Body)
	var out T
	if err := dec.Decode(&out); err != nil {
		if errors.Is(err, io.EOF) && allowEmpty {
			return zero, nil
		}
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return zero, NewStatusError(http.StatusRequestEntityTooLarge, "request body too large", err)
		}
		return zero, NewStatusError(http.StatusBadRequest, "invalid JSON request body", err)
	}

	// 确保首个 JSON 值后不存在拼接的第 2 段恶意 JSON 载荷
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return zero, NewStatusError(http.StatusRequestEntityTooLarge, "request body too large", err)
		}
		return zero, BadRequest("unexpected trailing data after JSON body")
	}
	return out, nil
}

// Handle 将纯业务函数 `func(*http.Request) (Resp, error)` 包装为标准 http.HandlerFunc（零反射）。
func Handle[Resp any](fn func(r *http.Request) (Resp, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := fn(r)
		if err != nil {
			WriteError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, resp)
	}
}

// HandleBody 自动完成有界 JSON 解码后调用强类型业务函数，并统一输出 JSON 或错误响应。
func HandleBody[Req, Resp any](fn func(r *http.Request, req Req) (Resp, error)) http.HandlerFunc {
	return handleBodyWithMode(false, fn)
}

// HandleBodyAllowEmpty 允许空 Body 回退为零值 Req，同时拦截超限或畸形 JSON。
func HandleBodyAllowEmpty[Req, Resp any](fn func(r *http.Request, req Req) (Resp, error)) http.HandlerFunc {
	return handleBodyWithMode(true, fn)
}

func handleBodyWithMode[Req, Resp any](allowEmpty bool, fn func(r *http.Request, req Req) (Resp, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := DecodeJSON[Req](w, r, DefaultMaxBodyBytes, allowEmpty)
		if err != nil {
			WriteError(w, err)
			return
		}
		resp, err := fn(r, req)
		if err != nil {
			WriteError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, resp)
	}
}
