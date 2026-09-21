package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wneessen/go-mail"
)

type MailService interface {
	SendVerificationCode(ctx context.Context, toEmail, customerName string, code int) error
}

type SmtpMailService struct {
	host     string
	port     int
	username string
	password string
	from     string
}

func NewMailService() *SmtpMailService {
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if port == 0 {
		port = 587
	}

	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = "no-reply@neocentra.bank"
	}

	pass := strings.ReplaceAll(os.Getenv("SMTP_PASS"), " ", "")

	return &SmtpMailService{
		host:     os.Getenv("SMTP_HOST"),
		port:     port,
		username: os.Getenv("SMTP_USER"),
		password: pass,
		from:     from,
	}
}

func (s *SmtpMailService) SendVerificationCode(ctx context.Context, toEmail, customerName string, code int) error {
	codeStr := fmt.Sprintf("%05d", code)
	spacedCode := strings.Join(strings.Split(codeStr, ""), " ")

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Kode Verifikasi Neocentra</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #F8FAFC; margin: 0; padding: 24px; color: #0F172A; }
    .container { max-width: 520px; margin: 0 auto; background: #FFFFFF; border-radius: 16px; padding: 32px; border: 1px solid #E2E8F0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
    .header { text-align: center; margin-bottom: 24px; }
    .brand { font-size: 24px; font-weight: 800; color: #0066FF; letter-spacing: -0.5px; }
    .badge { display: inline-block; background-color: #EBF3FF; color: #0066FF; font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 9999px; margin-top: 8px; }
    .greeting { font-size: 16px; margin-bottom: 12px; color: #1E293B; }
    .desc { font-size: 14px; color: #64748B; line-height: 1.6; margin-bottom: 24px; }
    .otp-box { background: linear-gradient(135deg, #0A2540 0%%, #0066FF 100%%); border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 24px; }
    .otp-code { font-size: 36px; font-weight: 800; color: #FFFFFF; letter-spacing: 8px; font-family: monospace; }
    .otp-timer { color: #EBF3FF; font-size: 12px; margin-top: 6px; }
    .warning-box { background-color: #FFFBEB; border-left: 4px solid #F59E0B; padding: 12px 16px; border-radius: 6px; font-size: 13px; color: #92400E; margin-bottom: 24px; line-height: 1.5; }
    .footer { text-align: center; font-size: 11px; color: #94A3B8; border-top: 1px solid #F1F5F9; padding-top: 16px; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">NeoCentra Bank</div>
      <div class="badge">Keamanan Perbankan Digital</div>
    </div>
    <div class="greeting">Halo, <strong>%s</strong></div>
    <div class="desc">
      Terima kasih telah melakukan pendaftaran rekening baru di Neocentra Digital Bank. Gunakan kode verifikasi di bawah ini untuk mengonfirmasi kepemilikan email Anda.
    </div>
    <div class="otp-box">
      <div class="otp-code">%s</div>
      <div class="otp-timer">Kode ini berlaku selama 5 menit (300 detik)</div>
    </div>
    <div class="warning-box">
      <strong>PENTING:</strong> JANGAN PERNAH memberikan kode verifikasi ini kepada siapa pun, termasuk pihak yang mengatasnamakan Neocentra Bank. Tim bank tidak pernah meminta kode rahasia ini.
    </div>
    <div class="footer">
      Email ini dibuat secara otomatis oleh sistem perbankan Neocentra.<br>
      PT Neocentra Bank Indonesia berizin dan diawasi oleh Otoritas Jasa Keuangan (OJK) serta merupakan peserta penjaminan Lembaga Penjamin Simpanan (LPS).
    </div>
  </div>
</body>
</html>`, customerName, spacedCode)

	// In test/local dev or when SMTP is not configured, log clearly and return nil
	if s.host == "" || os.Getenv("APP_ENV") == "test" {
		log.Printf("[MAIL SERVICE] [MOCK SEND] To: %s | OTP Code: %s | Customer: %s", toEmail, codeStr, customerName)
		return nil
	}

	msg := mail.NewMsg()
	if err := msg.From(s.from); err != nil {
		return fmt.Errorf("failed to set from address: %w", err)
	}
	if err := msg.To(toEmail); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}
	msg.Subject("Kode Verifikasi Pendaftaran Rekening Neocentra Bank")
	msg.SetBodyString(mail.TypeTextHTML, htmlBody)

	clientOpts := []mail.Option{
		mail.WithPort(s.port),
		mail.WithTimeout(10 * time.Second),
	}
	if s.username != "" && s.password != "" {
		clientOpts = append(clientOpts, mail.WithSMTPAuth(mail.SMTPAuthPlain), mail.WithUsername(s.username), mail.WithPassword(s.password))
	} else {
		clientOpts = append(clientOpts, mail.WithTLSPolicy(mail.TLSOpportunistic))
	}

	client, err := mail.NewClient(s.host, clientOpts...)
	if err != nil {
		return fmt.Errorf("failed to initialize mail client: %w", err)
	}

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		log.Printf("[MAIL ERROR] Failed to send email via SMTP to %s: %v", toEmail, err)
		return fmt.Errorf("gagal mengirim email verifikasi: %w", err)
	}

	log.Printf("[MAIL SUCCESS] Verification email sent to %s", toEmail)
	return nil
}
