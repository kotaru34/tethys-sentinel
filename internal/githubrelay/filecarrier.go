package githubrelay

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const FileRequestRoot = ".tethys-sentinel/relay-requests"

var (
	fileRequestNamePattern = regexp.MustCompile(`^[0-9]{20}\.req$`)
	ErrInvalidFileCarrier  = errors.New("invalid GitHub fallback request file")
)

type GitHubRequestFile struct {
	Name      string
	Path      string
	SHA       string
	Size      int
	Body      string
	CommitSHA string
	Actor     GitHubUser
}

type githubContentsEntry struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	SHA      string `json:"sha"`
	Size     int    `json:"size"`
	Encoding string `json:"encoding,omitempty"`
	Content  string `json:"content,omitempty"`
}

type githubCommitListEntry struct {
	SHA    string     `json:"sha"`
	Author GitHubUser `json:"author"`
}

func FileRequestPath(sessionID string, sequence uint64) (string, error) {
	sessionID = strings.TrimSpace(sessionID)
	if !sessionIDPattern.MatchString(sessionID) {
		return "", errors.New("invalid relay session id")
	}
	if sequence == 0 {
		return "", errors.New("relay request sequence must be positive")
	}
	return path.Join(FileRequestRoot, sessionID, fmt.Sprintf("%020d.req", sequence)), nil
}

func (c *GitHubClient) RequestFiles(ctx context.Context, repository, sessionID string) ([]GitHubRequestFile, error) {
	if !sessionIDPattern.MatchString(strings.TrimSpace(sessionID)) {
		return nil, errors.New("invalid relay session id")
	}
	owner, name, err := splitRepository(repository)
	if err != nil {
		return nil, err
	}
	dir := path.Join(FileRequestRoot, sessionID)
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(name), escapeGitHubPath(dir))
	var entries []githubContentsEntry
	status, err := c.doContentsJSONStatus(ctx, http.MethodGet, apiPath, nil, &entries)
	if err != nil {
		var httpErr *GitHubHTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected GitHub contents status %d", status)
	}
	out := make([]GitHubRequestFile, 0, len(entries))
	for _, entry := range entries {
		if entry.Type != "file" || !fileRequestNamePattern.MatchString(entry.Name) {
			continue
		}
		expected := path.Join(dir, entry.Name)
		if entry.Path != expected {
			continue
		}
		out = append(out, GitHubRequestFile{Name: entry.Name, Path: entry.Path, SHA: entry.SHA, Size: entry.Size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *GitHubClient) RequestFile(ctx context.Context, repository, filePath string) (GitHubRequestFile, error) {
	if err := validateFileRequestPath(filePath); err != nil {
		return GitHubRequestFile{}, err
	}
	owner, name, err := splitRepository(repository)
	if err != nil {
		return GitHubRequestFile{}, err
	}
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(name), escapeGitHubPath(filePath))
	var entry githubContentsEntry
	status, err := c.doContentsJSONStatus(ctx, http.MethodGet, apiPath, nil, &entry)
	if err != nil {
		return GitHubRequestFile{}, err
	}
	if status != http.StatusOK || entry.Type != "file" || entry.Path != filePath {
		return GitHubRequestFile{}, fmt.Errorf("%w: path is not a regular file", ErrInvalidFileCarrier)
	}
	if entry.Size < 1 || entry.Size > maxCommentBytes {
		return GitHubRequestFile{}, fmt.Errorf("%w: file exceeds relay transport limit", ErrInvalidFileCarrier)
	}
	if entry.Encoding != "base64" {
		return GitHubRequestFile{}, fmt.Errorf("%w: unsupported encoding %q", ErrInvalidFileCarrier, entry.Encoding)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(entry.Content, "\n", ""))
	if err != nil {
		return GitHubRequestFile{}, fmt.Errorf("%w: decode content: %v", ErrInvalidFileCarrier, err)
	}
	if len(raw) < 1 || len(raw) > maxCommentBytes {
		return GitHubRequestFile{}, fmt.Errorf("%w: decoded content exceeds relay transport limit", ErrInvalidFileCarrier)
	}

	commitPath := fmt.Sprintf(
		"/repos/%s/%s/commits?path=%s&per_page=2",
		url.PathEscape(owner), url.PathEscape(name), url.QueryEscape(filePath),
	)
	var commits []githubCommitListEntry
	status, err = c.doContentsJSONStatus(ctx, http.MethodGet, commitPath, nil, &commits)
	if err != nil {
		return GitHubRequestFile{}, err
	}
	if status != http.StatusOK || len(commits) != 1 {
		return GitHubRequestFile{}, fmt.Errorf("%w: file is not immutable single-commit content", ErrInvalidFileCarrier)
	}
	if commits[0].SHA == "" || commits[0].Author.ID <= 0 {
		return GitHubRequestFile{}, fmt.Errorf("%w: file has no stable commit actor", ErrInvalidFileCarrier)
	}

	return GitHubRequestFile{
		Name:      entry.Name,
		Path:      entry.Path,
		SHA:       entry.SHA,
		Size:      entry.Size,
		Body:      string(raw),
		CommitSHA: commits[0].SHA,
		Actor:     commits[0].Author,
	}, nil
}

func (c *GitHubClient) doContentsJSONStatus(ctx context.Context, method, apiPath string, body any, out any) (int, error) {
	token, err := c.installationContentsToken(ctx)
	if err != nil {
		return 0, err
	}
	return c.doJSON(ctx, method, apiPath, body, token, "", out, nil, nil)
}

func (c *GitHubClient) installationContentsToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.contentsToken != "" && time.Until(c.contentsTokenExpiry) > 5*time.Minute {
		return c.contentsToken, nil
	}
	jwt, err := c.appJWT(time.Now().UTC())
	if err != nil {
		return "", err
	}
	var response githubInstallationToken
	apiPath := fmt.Sprintf("/app/installations/%d/access_tokens", c.installationID)
	request := map[string]any{
		"permissions": map[string]string{
			"contents": "read",
			"issues":   "write",
			"metadata": "read",
		},
	}
	if _, err := c.doJSON(ctx, http.MethodPost, apiPath, request, jwt, "", &response, nil, nil); err != nil {
		return "", fmt.Errorf("mint GitHub App contents token: %w", err)
	}
	if strings.TrimSpace(response.Token) == "" || response.ExpiresAt.IsZero() {
		return "", errors.New("GitHub returned an invalid contents installation token response")
	}
	c.contentsToken = response.Token
	c.contentsTokenExpiry = response.ExpiresAt
	return c.contentsToken, nil
}

func validateFileRequestPath(filePath string) error {
	filePath = strings.TrimSpace(filePath)
	parts := strings.Split(filePath, "/")
	if len(parts) != 4 || parts[0] != ".tethys-sentinel" || parts[1] != "relay-requests" {
		return errors.New("invalid GitHub fallback request path")
	}
	if !sessionIDPattern.MatchString(parts[2]) || !fileRequestNamePattern.MatchString(parts[3]) {
		return errors.New("invalid GitHub fallback request path")
	}
	sequenceText := strings.TrimSuffix(parts[3], ".req")
	sequence, err := strconv.ParseUint(sequenceText, 10, 64)
	if err != nil || sequence == 0 {
		return errors.New("invalid GitHub fallback request sequence")
	}
	expected, err := FileRequestPath(parts[2], sequence)
	if err != nil || expected != filePath {
		return errors.New("invalid GitHub fallback request path")
	}
	return nil
}

func escapeGitHubPath(value string) string {
	parts := strings.Split(value, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
