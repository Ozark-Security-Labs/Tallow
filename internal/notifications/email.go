package notifications

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

type SMTPSender interface {
	SendMail(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
}

type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	PasswordRef string
	From        string
	To          []string
}

type EmailChannel struct {
	Config SMTPConfig
	Sender SMTPSender
}

func (c EmailChannel) Send(ctx context.Context, route Route, msg Message) (string, error) {
	_ = ctx
	if c.Sender == nil {
		return "", fmt.Errorf("smtp sender unavailable")
	}
	addr := fmt.Sprintf("%s:%d", c.Config.Host, c.Config.Port)
	body := "Subject: " + sanitizeHeader(msg.Subject) + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + msg.Text
	if err := c.Sender.SendMail(addr, nil, c.Config.From, c.Config.To, []byte(body)); err != nil {
		return "", fmt.Errorf("smtp delivery failed: %s", Redact(err.Error()))
	}
	return "smtp:" + strings.TrimSpace(route.ID), nil
}

func sanitizeHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}
