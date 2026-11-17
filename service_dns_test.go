package anytls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type discardHandler struct{}

func (discardHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
}

// The DNS handler sees the user the connection authenticated as.
func TestServiceDNSHandlerSeesUser(t *testing.T) {
	users := make(chan string, 1)
	service, err := NewService(ServiceConfig{
		Users:         []User{{Name: "alice", Password: "secret"}},
		PaddingScheme: padding.DefaultPaddingScheme,
		Handler:       discardHandler{},
		Logger:        logger.NOP(),
		DNSHandler: func(ctx context.Context, request []byte) ([]byte, error) {
			user, _ := auth.UserFromContext[string](ctx)
			users <- user
			return request, nil
		},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	client, err := NewClient(context.Background(), ClientConfig{
		Password: "secret",
		Logger:   logger.NOP(),
		DialOut: func(ctx context.Context) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go service.NewConnection(context.Background(), serverConn, M.Socksaddr{}, nil)
			return clientConn, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := client.ExchangeDNS(ctx, []byte("query"))
	if err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	if string(response) != "query" {
		t.Fatalf("response = %q", response)
	}
	if user := <-users; user != "alice" {
		t.Fatalf("handler saw user %q", user)
	}
}
