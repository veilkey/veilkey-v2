package bridge

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// MattermostBridge polls a Mattermost channel for new posts via the REST API.
type MattermostBridge struct {
	BaseURL    string // e.g. "http://10.50.0.202:8065"
	Token      string // bot token
	ChannelID  string
	PostsCh    chan Post
	httpClient *http.Client

	mu            sync.Mutex
	lastFetchedAt int64 // unix millis of the most recent post we've seen
	firstPoll     bool
}

// Post is a minimal representation of a Mattermost post.
type Post struct {
	ID        string `json:"id"`
	ChannelID string `json:"channel_id"`
	UserID    string `json:"user_id"`
	Message   string `json:"message"`
	CreateAt  int64  `json:"create_at"`
}

type postsResponse struct {
	Order []string        `json:"order"`
	Posts map[string]Post `json:"posts"`
}

// NewMattermostBridge creates a bridge with a bounded post channel.
func NewMattermostBridge(baseURL, token, channelID string) *MattermostBridge {
	return &MattermostBridge{
		BaseURL:    baseURL,
		Token:      token,
		ChannelID:  channelID,
		PostsCh:    make(chan Post, 50),
		httpClient: &http.Client{Timeout: 15 * time.Second},
		firstPoll:  true,
	}
}

// fetchNewPosts retrieves recent posts from the channel.
//
// It applies per_page=50 to cap the number of posts returned by the API.
// On the first poll, only the timestamp of the newest post is recorded
// (no posts are emitted) so that a large backlog of historical messages
// does not flood or block the buffer.
func (b *MattermostBridge) fetchNewPosts() error {
	b.mu.Lock()
	since := b.lastFetchedAt
	isFirstPoll := b.firstPoll
	b.mu.Unlock()

	url := fmt.Sprintf("%s/api/v4/channels/%s/posts?per_page=50", b.BaseURL, b.ChannelID)
	if since > 0 {
		url += fmt.Sprintf("&since=%d", since)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.Token)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var pr postsResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return fmt.Errorf("decode posts: %w", err)
	}

	// Track the newest timestamp we see in this batch.
	var maxCreateAt int64
	for _, p := range pr.Posts {
		if p.CreateAt > maxCreateAt {
			maxCreateAt = p.CreateAt
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// First poll: just record the high-water mark so subsequent polls
	// only return genuinely new messages. This prevents a burst of old
	// messages from overflowing the channel buffer.
	if isFirstPoll {
		b.firstPoll = false
		if maxCreateAt > 0 {
			b.lastFetchedAt = maxCreateAt
		}
		return nil
	}

	// Emit posts that are newer than our last checkpoint, oldest first.
	for i := len(pr.Order) - 1; i >= 0; i-- {
		p, ok := pr.Posts[pr.Order[i]]
		if !ok || p.CreateAt <= since {
			continue
		}
		select {
		case b.PostsCh <- p:
		default:
			// Channel full -- drop to avoid blocking the poll loop.
		}
	}

	if maxCreateAt > b.lastFetchedAt {
		b.lastFetchedAt = maxCreateAt
	}
	return nil
}
