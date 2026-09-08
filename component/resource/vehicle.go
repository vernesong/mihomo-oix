package resource

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/metacubex/http"
)

const (
	DefaultHttpTimeout = time.Second * 20

	fileMode os.FileMode = 0o644
)

var (
	etag = false
)

func ETag() bool {
	return etag
}

func SetETag(b bool) {
	etag = b
}

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() P.VehicleType {
	return P.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (f *FileVehicle) Url() string {
	return "file://" + f.path
}

func (f *FileVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	buf, err = os.ReadFile(f.path)
	if err != nil {
		return
	}
	hash = utils.MakeHash(buf)
	return
}

func (f *FileVehicle) Proxy() string {
	return ""
}

func (f *FileVehicle) Write(buf []byte) error {
	return f.WriteContext(context.Background(), buf)
}

func (f *FileVehicle) WriteContext(ctx context.Context, buf []byte) error {
	return utils.WriteFileAtomic(ctx, f.path, buf, fileMode)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

type HTTPVehicle struct {
	url       string
	path      string
	proxy     string
	header    http.Header
	timeout   time.Duration
	sizeLimit int64
	inRead    func(response *http.Response)
	options   []mihomoHttp.Option
}

func (h *HTTPVehicle) Url() string {
	return h.url
}

func (h *HTTPVehicle) Type() P.VehicleType {
	return P.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Proxy() string {
	return h.proxy
}

func (h *HTTPVehicle) Write(buf []byte) error {
	return h.WriteContext(context.Background(), buf)
}

func (h *HTTPVehicle) WriteContext(ctx context.Context, buf []byte) error {
	return utils.WriteFileAtomic(ctx, h.path, buf, fileMode)
}

func (h *HTTPVehicle) SetInRead(fn func(response *http.Response)) {
	h.inRead = fn
}

func (h *HTTPVehicle) Read(ctx context.Context, oldHash utils.HashType) ([]byte, utils.HashType, error) {
	return h.ReadValidated(ctx, oldHash, nil)
}

// ReadValidated checks complete candidates before publishing metadata or choosing a route.
func (h *HTTPVehicle) ReadValidated(ctx context.Context, oldHash utils.HashType, validate func([]byte) error, trustedCache ...bool) (buf []byte, hash utils.HashType, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	header := h.header
	allowConditional := oldHash.IsValid() && (validate == nil || len(trustedCache) > 0 && trustedCache[0])
	// Only our stored validator is tied to oldHash. User-supplied conditions
	// could select a body-less 304 without any matching cached representation.
	if header != nil {
		header = header.Clone()
		for key := range header {
			if strings.EqualFold(key, "If-None-Match") || strings.EqualFold(key, "If-Modified-Since") {
				delete(header, key)
			}
		}
	}
	setIfNoneMatch := false
	if allowConditional && etag {
		etagWithHash := cachefile.Cache().GetETagWithHash(h.url)
		if oldHash.Equal(etagWithHash.Hash) && etagWithHash.ETag != "" {
			if header == nil {
				header = http.Header{}
			}
			header.Set("If-None-Match", etagWithHash.ETag)
			setIfNoneMatch = true
		}
	}
	resp, buf, err := mihomoHttp.Get(ctx, h.url, header, h.sizeLimit, func(resp *http.Response, data []byte) error {
		if resp.StatusCode == http.StatusNotModified {
			return nil
		}
		if validate != nil {
			return validate(data)
		}
		return nil
	}, append(append([]mihomoHttp.Option{}, h.options...), mihomoHttp.WithSpecialProxy(h.proxy))...)
	if err != nil {
		return nil, hash, err
	}
	if h.inRead != nil {
		h.inRead(resp)
	}
	if setIfNoneMatch && resp.StatusCode == http.StatusNotModified {
		return nil, oldHash, nil
	}
	hash = utils.MakeHash(buf)
	if etag {
		cachefile.Cache().SetETagWithHash(h.url, cachefile.EtagWithHash{
			Hash: hash,
			ETag: resp.Header.Get("ETag"),
			Time: time.Now(),
		})
	}
	return
}

func NewHTTPVehicle(url string, path string, proxy string, header http.Header, timeout time.Duration, sizeLimit int64, options ...mihomoHttp.Option) *HTTPVehicle {
	return &HTTPVehicle{
		url:       url,
		path:      path,
		proxy:     proxy,
		header:    header,
		timeout:   timeout,
		sizeLimit: sizeLimit,
		options:   append([]mihomoHttp.Option{}, options...),
	}
}
