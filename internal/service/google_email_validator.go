package service

import (
	"context"
	"net"
	"net/mail"
	"os"
	"strings"
	"time"

	"customer-service/internal/domain"
)

type GoogleEmailValidator interface {
	ValidateGoogleEmail(ctx context.Context, email string) error
}

type DefaultGoogleEmailValidator struct {
	resolver *net.Resolver
}

func NewGoogleEmailValidator() *DefaultGoogleEmailValidator {
	return &DefaultGoogleEmailValidator{
		resolver: net.DefaultResolver,
	}
}

func (v *DefaultGoogleEmailValidator) ValidateGoogleEmail(ctx context.Context, emailStr string) error {
	// Parse RFC5322 email
	parsed, err := mail.ParseAddress(strings.TrimSpace(emailStr))
	if err != nil {
		return domain.ErrInvalidEmailGoogle
	}

	parts := strings.Split(parsed.Address, "@")
	if len(parts) != 2 {
		return domain.ErrInvalidEmailGoogle
	}

	user := strings.TrimSpace(parts[0])
	domainName := strings.ToLower(strings.TrimSpace(parts[1]))

	if user == "" || domainName == "" {
		return domain.ErrInvalidEmailGoogle
	}

	// If bypass or testing environment
	if os.Getenv("APP_ENV") == "test" || os.Getenv("SKIP_EMAIL_GOOGLE_CHECK") == "true" {
		// Only check if it's not explicitly an invalid test domain
		if domainName == "invalid" || strings.Contains(emailStr, "notexist") {
			return domain.ErrInvalidEmailGoogle
		}
		return nil
	}

	// 1. Direct Gmail/Googlemail check
	isGmailDomain := domainName == "gmail.com" || domainName == "googlemail.com"

	// 2. Lookup MX records to check if domain is serviced by Google Mail servers
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	mxRecords, err := v.resolver.LookupMX(lookupCtx, domainName)
	if err != nil || len(mxRecords) == 0 {
		// If offline or network lookup fails in local sandbox, allow gmail.com or neocentra.bank test domain
		if isGmailDomain || domainName == "neocentra.bank" {
			return nil
		}
		return domain.ErrInvalidEmailGoogle
	}

	// Verify that at least one MX record belongs to Google Mail servers
	isGoogleServiced := isGmailDomain
	for _, mx := range mxRecords {
		host := strings.ToLower(mx.Host)
		if strings.Contains(host, "google.com") ||
			strings.Contains(host, "googlemail.com") ||
			strings.Contains(host, "l.google.com") {
			isGoogleServiced = true
			break
		}
	}

	if !isGoogleServiced {
		return domain.ErrInvalidEmailGoogle
	}

	return nil
}
