package utils

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/crypto/bcrypt"
)

func ParseUsers(usersStr []string, userAttributes map[string]model.UserAttributes) (*[]model.LocalUser, error) {
	var users []model.LocalUser

	if len(usersStr) == 0 {
		return nil, nil
	}

	for i, entry := range usersStr {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		parsed, err := ParseUserEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("user entry %d: %w", i+1, err)
		}
		for _, user := range parsed {
			if attrs, ok := userAttributes[user.Username]; ok {
				user.Attributes = attrs
			}
			users = append(users, user)
		}
	}

	return &users, nil
}

// ParseUserEntry parses one entry (e.g. a users file line). Like v4, an entry may hold several comma-separated
// users. It is only split when there are at least two users and every part is a valid user with a bcrypt hash,
// so usernames containing a comma keep working and a malformed line is never split into different users.
func ParseUserEntry(entry string) ([]model.LocalUser, error) {
	if strings.Contains(entry, ",") {
		var users []model.LocalUser
		parts := strings.Split(entry, ",")
		for i, part := range parts {
			if strings.TrimSpace(part) == "" {
				// a single trailing comma is tolerated (v4 wrote one), any other empty
				// part means this is not a clean list, so do not reinterpret usernames
				if i == len(parts)-1 {
					continue
				}
				users = nil
				break
			}
			user, err := ParseUser(strings.TrimSpace(part))
			if err != nil || !isBcryptHash(user.Password) {
				users = nil
				break
			}
			users = append(users, *user)
		}
		// A single user with only a tolerated trailing comma is still a clean list; return it
		// so a v4 file with one user per line (each ending in a comma) keeps working.
		trailingOnly := len(users) == 1 && len(parts) == 2 && strings.TrimSpace(parts[1]) == ""
		if len(users) > 1 || trailingOnly {
			return users, nil
		}
	}

	user, err := ParseUser(strings.TrimSpace(entry))
	if err != nil {
		return nil, err
	}

	// password hashes and TOTP secrets never contain a comma, this is a list with an invalid user in it
	if strings.Contains(user.Password, ",") || strings.Contains(user.TOTPSecret, ",") {
		return nil, errors.New("invalid user format, expected username:password_hash[:totp_secret] separated by commas")
	}

	return []model.LocalUser{*user}, nil
}

// isBcryptHash reports whether s is exactly one bcrypt hash (bcrypt ignores trailing bytes, so the length is checked too)
func isBcryptHash(s string) bool {
	if len(s) != 60 {
		return false
	}
	if _, err := bcrypt.Cost([]byte(s)); err != nil {
		return false
	}
	// bcrypt.Cost only validates the "$2x$cost$" prefix, not the body, so a value like
	// "$2a$10$" + strings.Repeat("!", 53) would pass. Check the 22-char salt and 31-char
	// hash that follow use the bcrypt base64 alphabet so a malformed body is not mistaken
	// for a real hash and used to split an entry into separate users.
	for i := 7; i < len(s); i++ {
		c := s[i]
		if c != '.' && c != '/' && (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func GetUsers(usersCfg []string, usersPath string, userAttributes map[string]model.UserAttributes) (*[]model.LocalUser, error) {
	usersStr, err := GetStringList(usersCfg, usersPath)
	if err != nil {
		return nil, err
	}

	return ParseUsers(usersStr, userAttributes)
}

func ParseUser(userStr string) (*model.LocalUser, error) {
	if strings.Contains(userStr, "$$") {
		userStr = strings.ReplaceAll(userStr, "$$", "$")
	}

	parts := strings.SplitN(userStr, ":", 4)

	if len(parts) < 2 || len(parts) > 3 {
		return nil, errors.New("invalid user format, expected username:password_hash[:totp_secret]")
	}

	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, errors.New("invalid user format, expected username:password_hash[:totp_secret]")
		}
		parts[i] = trimmed
	}

	user := model.LocalUser{
		Username: parts[0],
		Password: parts[1],
	}

	if len(parts) == 3 {
		user.TOTPSecret = parts[2]
	}

	return &user, nil
}

func CompileUserEmail(username string, domain string) string {
	_, err := mail.ParseAddress(username)

	if err != nil {
		return fmt.Sprintf("%s@%s", strings.ToLower(username), domain)
	}

	return username
}
