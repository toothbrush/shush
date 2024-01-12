package awsmeta

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// GetMetaData ... fetch AWS meta-data.
func GetMetaData(path string) ([]byte, error) {
	url := "http://169.254.169.254/latest/meta-data/" + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("awsmeta: couldn't create request: %w", err)
	}
	client := http.Client{
		Timeout: time.Millisecond * 100,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("awsmeta: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("awsmeta: code %d returned for url %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("awsmeta: failed to read response body: %w", err)
	}

	return []byte(body), err
}

// GetRegion ... get the effective EC2 region.
func GetRegion() (string, error) {
	path := "placement/availability-zone"

	resp, err := GetMetaData(path)
	if err != nil {
		return "", fmt.Errorf("awsmeta: couldn't get metadata: %w", err)
	}

	az := string(resp)
	if az == "" {
		return "", fmt.Errorf("awsmeta: received empty AZ")
	}

	// Instead of us-west-2a, just return us-west-2
	return az[:len(az)-1], nil
}
