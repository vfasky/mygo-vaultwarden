// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/mail"
	"strings"
)

func accountEmail(email string) (string, error) {
	email = vaultcrypto.NormalizeEmail(email)
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || len(email) > 254 {
		return "", ErrValidation
	}
	return email, nil
}
func accountNewKDF(k vaultcrypto.KDF) error {
	if k.Type == 0 && (k.Iterations < 100000 || k.Iterations > 2000000 || k.Memory != 0 || k.Parallelism != 0) {
		return ErrKDF
	}
	if k.Type == 1 && (k.Iterations < 2 || k.Iterations > 10 || k.Memory < 16 || k.Memory > 256 || k.Parallelism < 1 || k.Parallelism > 16) {
		return ErrKDF
	}
	if k.Type != 0 && k.Type != 1 {
		return ErrKDF
	}
	return nil
}

// AccountRegistrationVerification distinguishes SMTP delivery from a returned
// token. Tokens remain secret and are never interpreted as authentication.
type AccountRegistrationVerification struct {
	EmailSent bool
	Token     string
}

func (c *Client) AccountSendRegistrationEmail(ctx context.Context, email, name string) (AccountRegistrationVerification, error) {
	email, err := accountEmail(email)
	if err != nil {
		return AccountRegistrationVerification{}, err
	}
	if len(name) > 50 {
		return AccountRegistrationVerification{}, ErrValidation
	}
	body, _ := json.Marshal(map[string]string{"email": email, "name": name})
	status, data, err := c.request(ctx, "POST", "/identity/accounts/register/send-verification-email", "application/json", string(body), "")
	if err != nil {
		return AccountRegistrationVerification{}, &MutationUncertainError{Cause: err}
	}
	if status == 204 {
		return AccountRegistrationVerification{EmailSent: true}, nil
	}
	var token string
	if status != 200 {
		return AccountRegistrationVerification{}, mutationStatusError(status)
	}
	if json.Unmarshal(data, &token) != nil || token == "" || len(token) > 16384 {
		return AccountRegistrationVerification{}, &MutationUncertainError{Cause: ErrProtocol}
	}
	return AccountRegistrationVerification{Token: token}, nil
}

// AccountRegister generates a fresh symmetric user key and RSA keypair locally.
// It does not create a session; success is followed by the ordinary login flow.
func (c *Client) AccountRegister(ctx context.Context, email string, password []byte, kdf vaultcrypto.KDF, hint, verificationToken string) error {
	email, err := accountEmail(email)
	if err != nil {
		return err
	}
	if err = accountNewKDF(kdf); err != nil {
		return err
	}
	if len(password) < 12 || len(hint) > 1024 || verificationToken == "" || len(verificationToken) > 16384 {
		return ErrValidation
	}
	if err = (AccountPasswordPolicy{MinLength: 12}).Check(ctx, password, email, false); err != nil {
		return err
	}
	master, err := vaultcrypto.DeriveMaster(password, email, kdf)
	if err != nil {
		return err
	}
	defer clear(master)
	stretched, err := vaultcrypto.StretchMaster(master)
	if err != nil {
		return err
	}
	defer clear(stretched)
	key := make([]byte, 64)
	defer clear(key)
	if _, err = rand.Read(key); err != nil {
		return ErrEncryption
	}
	wrapped, err := vaultcrypto.EncryptString(key, stretched)
	if err != nil {
		return err
	}
	keys, err := makeOrganizationKeyPair(key)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Email string `json:"email"`
		vaultcrypto.KDF
		Hash  string              `json:"masterPasswordHash"`
		Key   string              `json:"key"`
		Keys  organizationKeyPair `json:"keys"`
		Hint  string              `json:"masterPasswordHint"`
		Token string              `json:"emailVerificationToken"`
	}{email, kdf, vaultcrypto.AuthorizationHash(master, password), wrapped, keys, hint, verificationToken})
	if err != nil {
		return ErrProtocol
	}
	defer clear(body)
	if ctx.Err() != nil {
		return ErrCancelled
	}
	status, _, err := c.request(ctx, "POST", "/identity/accounts/register/finish", "application/json", string(body), "")
	if err != nil {
		return &MutationUncertainError{Cause: err}
	}
	if status != 200 {
		return mutationStatusError(status)
	}
	return nil
}
func (c *Client) AccountPasswordHint(ctx context.Context, email string) error {
	email, err := accountEmail(email)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"email": email})
	status, _, err := c.request(ctx, "POST", "/api/accounts/password-hint", "application/json", string(body), "")
	if err != nil {
		return err
	}
	if status != 200 {
		return statusError(status)
	}
	return nil
}
func (c *Client) AccountVerifyEmailToken(ctx context.Context, userID, token string) error {
	if !validObjectID(userID) || strings.TrimSpace(token) == "" || len(token) > 16384 {
		return ErrValidation
	}
	body, _ := json.Marshal(map[string]string{"userId": userID, "token": token})
	defer clear(body)
	status, _, err := c.request(ctx, "POST", "/api/accounts/verify-email-token", "application/json", string(body), "")
	if err != nil {
		return &MutationUncertainError{Cause: err}
	}
	if status != 200 {
		return mutationStatusError(status)
	}
	return nil
}
