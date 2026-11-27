package config

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var updateRepoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func DefaultUpdate() Update {
	return Update{
		Repo:    DefaultUpdateRepo,
		Channel: DefaultUpdateChannel,
	}
}

func (u *Update) validate() error {
	u.Repo = strings.TrimSpace(u.Repo)
	if u.Repo == "" {
		u.Repo = DefaultUpdateRepo
	}
	if !updateRepoPattern.MatchString(u.Repo) {
		return errors.New("update.repo must be in 'owner/repo' format")
	}
	u.Channel = strings.ToLower(strings.TrimSpace(u.Channel))
	if u.Channel == "" {
		u.Channel = DefaultUpdateChannel
	}
	if u.Channel != "stable" && u.Channel != "prerelease" {
		return errors.New("update.channel must be stable or prerelease")
	}
	u.BaseURL = strings.TrimRight(strings.TrimSpace(u.BaseURL), "/")
	if u.BaseURL != "" {
		parsed, err := url.Parse(u.BaseURL)
		if err != nil || !AllowedGeoURL(parsed) {
			return errors.New("update.base_url requires HTTPS or an explicit loopback HTTP address")
		}
	}
	return nil
}
