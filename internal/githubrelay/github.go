package githubrelay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultGitHubAPI = "https://api.github.com"
	githubAPIVersion = "2022-11-28"
	githubUserAgent  = "tethys-sentinel-github-relay"
	maxGitHubBody    = 2 << 20
)

type GitHubAppConfig struct {
	AppID          int64
	InstallationID int64
	PrivateKeyFile string
	APIBase        string
	HTTPClient     *http.Client
}

type GitHubClient struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	baseURL        string
	http           *http.Client

	mu                  sync.Mutex
	token               string
	tokenExpiry         time.Time
	contentsToken       string
	contentsTokenExpiry time.Time
}

type GitHubRepository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
	Archived bool   `json:"archived"`
}

type GitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

type GitHubIssue struct {
	ID          int64       `json:"id"`
	Number      int         `json:"number"`
	State       string      `json:"state"`
	Title       string      `json:"title"`
	User        GitHubUser  `json:"user"`
	PullRequest interface{} `json:"pull_request,omitempty"`
}

type GitHubComment struct {
	ID        int64      `json:"id"`
	Body      string     `json:"body"`
	User      GitHubUser `json:"user"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type githubInstallationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type GitHubHTTPError struct {
	StatusCode int
	Message    string
	RetryAfter time.Duration
}

func (e *GitHubHTTPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("GitHub HTTP %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("GitHub HTTP %d", e.StatusCode)
}

func NewGitHubClient(cfg GitHubAppConfig) (*GitHubClient, error) {
	if cfg.AppID <= 0 || cfg.InstallationID <= 0 {
		return nil, errors.New("GitHub App ID and installation ID are required")
	}
	key, err := readGitHubPrivateKey(cfg.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.APIBase), "/")
	if base == "" {
		base = defaultGitHubAPI
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("GitHub API base must be a valid HTTPS origin")
	}
	client := cfg.HTTPClient
	if client == nil {
		transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true}
		client = &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &GitHubClient{
		appID: cfg.AppID, installationID: cfg.InstallationID, privateKey: key,
		baseURL: base, http: client,
	}, nil
}

func (c *GitHubClient) Repository(ctx context.Context, repository string) (GitHubRepository, error) {
	owner, name, err := splitRepository(repository)
	if err != nil {
		return GitHubRepository{}, err
	}
	var out GitHubRepository
	err = c.doInstallationJSON(ctx, http.MethodGet, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), nil, "", &out, nil)
	return out, err
}

func (c *GitHubClient) Issue(ctx context.Context, repository string, number int) (GitHubIssue, error) {
	if number <= 0 {
		return GitHubIssue{}, errors.New("GitHub issue number must be positive")
	}
	owner, name, err := splitRepository(repository)
	if err != nil {
		return GitHubIssue{}, err
	}
	var out GitHubIssue
	path := fmt.Sprintf("/repos/%s/%s/issues/%d", url.PathEscape(owner), url.PathEscape(name), number)
	err = c.doInstallationJSON(ctx, http.MethodGet, path, nil, "", &out, nil)
	return out, err
}

// Comments returns at most the first 100 comments. The relay deliberately
// fails closed when GitHub reports another page; a noisy issue must not be able
// to hide authenticated requests beyond the polling window.
func (c *GitHubClient) Comments(ctx context.Context, repository string, number int, etag string) ([]GitHubComment, string, bool, error) {
	owner, name, err := splitRepository(repository)
	if err != nil {
		return nil, "", false, err
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100", url.PathEscape(owner), url.PathEscape(name), number)
	var comments []GitHubComment
	headers := make(http.Header)
	if strings.TrimSpace(etag) != "" {
		headers.Set("If-None-Match", etag)
	}
	respHeaders := make(http.Header)
	status, err := c.doInstallationJSONStatus(ctx, http.MethodGet, path, nil, "", &comments, headers, respHeaders)
	if err != nil {
		return nil, "", false, err
	}
	if status == http.StatusNotModified {
		return nil, etag, true, nil
	}
	if strings.Contains(respHeaders.Get("Link"), `rel="next"`) {
		return nil, respHeaders.Get("ETag"), false, errors.New("GitHub issue exceeds the relay's 100-comment safety window")
	}
	return comments, respHeaders.Get("ETag"), false, nil
}

func (c *GitHubClient) CreateComment(ctx context.Context, repository string, number int, body string) (GitHubComment, error) {
	if len(body) == 0 || len(body) > 60<<10 {
		return GitHubComment{}, errors.New("GitHub comment body is empty or exceeds relay limit")
	}
	owner, name, err := splitRepository(repository)
	if err != nil {
		return GitHubComment{}, err
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", url.PathEscape(owner), url.PathEscape(name), number)
	var out GitHubComment
	err = c.doInstallationJSON(ctx, http.MethodPost, path, map[string]string{"body": body}, "", &out, nil)
	return out, err
}

func (c *GitHubClient) doInstallationJSON(ctx context.Context, method, path string, body any, etag string, out any, headers http.Header) error {
	_, err := c.doInstallationJSONStatus(ctx, method, path, body, etag, out, headers, nil)
	return err
}

func (c *GitHubClient) doInstallationJSONStatus(ctx context.Context, method, path string, body any, etag string, out any, headers, responseHeaders http.Header) (int, error) {
	token, err := c.installationToken(ctx)
	if err != nil {
		return 0, err
	}
	return c.doJSON(ctx, method, path, body, token, etag, out, headers, responseHeaders)
}

func (c *GitHubClient) installationToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.tokenExpiry) > 5*time.Minute {
		return c.token, nil
	}
	jwt, err := c.appJWT(time.Now().UTC())
	if err != nil {
		return "", err
	}
	var response githubInstallationToken
	path := fmt.Sprintf("/app/installations/%d/access_tokens", c.installationID)
	request := map[string]any{
		"permissions": map[string]string{
			"issues":   "write",
			"metadata": "read",
		},
	}
	if _, err := c.doJSON(ctx, http.MethodPost, path, request, jwt, "", &response, nil, nil); err != nil {
		return "", fmt.Errorf("mint GitHub App installation token: %w", err)
	}
	if strings.TrimSpace(response.Token) == "" || response.ExpiresAt.IsZero() {
		return "", errors.New("GitHub returned an invalid installation token response")
	}
	c.token = response.Token
	c.tokenExpiry = response.ExpiresAt
	return c.token, nil
}

func (c *GitHubClient) appJWT(now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(c.appID, 10),
	})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *GitHubClient) doJSON(ctx context.Context, method, path string, body any, bearer, etag string, out any, headers, responseHeaders http.Header) (int, error) {
	var encoded io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		encoded = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, encoded)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("User-Agent", githubUserAgent)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("GitHub request: %w", err)
	}
	defer resp.Body.Close()
	if responseHeaders != nil {
		for key, values := range resp.Header {
			responseHeaders[key] = append([]string(nil), values...)
		}
	}
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, nil
	}
	limited := io.LimitReader(resp.Body, maxGitHubBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return resp.StatusCode, err
	}
	if len(data) > maxGitHubBody {
		return resp.StatusCode, errors.New("GitHub response exceeds client limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(data))
		var apiErr struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &apiErr) == nil && strings.TrimSpace(apiErr.Message) != "" {
			message = strings.TrimSpace(apiErr.Message)
		}
		return resp.StatusCode, &GitHubHTTPError{
			StatusCode: resp.StatusCode,
			Message:    message,
			RetryAfter: retryAfter(resp.Header, time.Now()),
		}
	}
	if out != nil && len(bytes.TrimSpace(data)) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode GitHub response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func retryAfter(header http.Header, now time.Time) time.Duration {
	if value := strings.TrimSpace(header.Get("Retry-After")); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	if header.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			delay := time.Unix(reset, 0).Sub(now)
			if delay > 0 {
				return delay
			}
		}
	}
	return 0
}

func readGitHubPrivateKey(path string) (*rsa.PrivateKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("GitHub App private key file is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect GitHub App private key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("GitHub App private key must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("GitHub App private key must not be group/other accessible")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("GitHub App private key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("GitHub App private key is not RSA PKCS#1 or PKCS#8")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("GitHub App private key is not RSA")
	}
	return key, nil
}

func splitRepository(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	parts := strings.Split(value, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", errors.New("repository must be owner/name")
	}
	for _, part := range parts {
		if strings.ContainsAny(part, "?#\\") || part == "." || part == ".." {
			return "", "", errors.New("repository contains invalid characters")
		}
	}
	return parts[0], parts[1], nil
}
