package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tomoyayamashita/chain-gate/internal/cache"
	"github.com/tomoyayamashita/chain-gate/internal/ecosystem"
	"github.com/tomoyayamashita/chain-gate/internal/logger"
	"github.com/tomoyayamashita/chain-gate/internal/policy"
)

// Server is a proxy server that intercepts package manager requests
type Server struct {
	addr            string
	listener        net.Listener
	detector        *ecosystem.Detector
	cache           *cache.ThreatIntelCache
	policyEngine    *policy.Engine
	logger          *logger.Logger
	shutdownChan    chan struct{}
	wg              sync.WaitGroup
	httpClient      *http.Client
}

// Config represents proxy server configuration
type Config struct {
	Addr         string
	Detector     *ecosystem.Detector
	Cache        *cache.ThreatIntelCache
	PolicyEngine *policy.Engine
	Logger       *logger.Logger
}

// NewServer creates a new proxy server
func NewServer(config Config) *Server {
	return &Server{
		addr:         config.Addr,
		detector:     config.Detector,
		cache:        config.Cache,
		policyEngine: config.PolicyEngine,
		logger:       config.Logger,
		shutdownChan: make(chan struct{}),
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Start starts the proxy server
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	s.listener = listener
	s.logger.Info("proxy_start", fmt.Sprintf("Proxy server started on %s", s.addr), nil)

	go s.acceptLoop()

	return nil
}

// Stop stops the proxy server
func (s *Server) Stop() error {
	close(s.shutdownChan)

	if s.listener != nil {
		s.listener.Close()
	}

	// Wait for all connections to close
	s.wg.Wait()

	s.logger.Info("proxy_stop", "Proxy server stopped", nil)
	return nil
}

// Addr returns the address the server is listening on
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownChan:
				return
			default:
				s.logger.Error("accept_error", "Failed to accept connection", map[string]interface{}{
					"error": err.Error(),
				})
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(clientConn net.Conn) {
	defer s.wg.Done()
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)

	// Read the first request
	req, err := http.ReadRequest(reader)
	if err != nil {
		s.logger.Error("read_request_error", "Failed to read request", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	// Handle CONNECT method (for HTTPS)
	if req.Method == http.MethodConnect {
		s.handleConnect(clientConn, req)
		return
	}

	// Handle regular HTTP request
	s.handleHTTP(clientConn, req)
}

// handleConnect handles HTTPS CONNECT requests
func (s *Server) handleConnect(clientConn net.Conn, req *http.Request) {
	// Extract host and port
	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Connect to the target server
	targetConn, err := net.DialTimeout("tcp", host, 30*time.Second)
	if err != nil {
		s.logger.Error("connect_error", "Failed to connect to target", map[string]interface{}{
			"host":  host,
			"error": err.Error(),
		})
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Send connection established response
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Create a TLS sniffer to inspect the SNI
	// For now, we'll do simple passthrough
	// TODO: Implement TLS interception if needed for deeper inspection

	// Bidirectional copy
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		io.Copy(targetConn, clientConn)
	}()
	go func() {
		defer s.wg.Done()
		io.Copy(clientConn, targetConn)
	}()

	// Note: For full HTTPS inspection, we would need to:
	// 1. Generate a dynamic certificate for the target host
	// 2. Perform TLS handshake with client using our certificate
	// 3. Perform TLS handshake with target server
	// 4. Inspect the decrypted traffic
	// This is complex and requires cert management, so for now we do passthrough
}

// handleHTTP handles regular HTTP requests
func (s *Server) handleHTTP(clientConn net.Conn, req *http.Request) {
	requestID := uuid.New().String()

	// Extract package identity from request
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	path := req.URL.Path
	if req.URL.RawQuery != "" {
		path = path + "?" + req.URL.RawQuery
	}

	packageIdentity := s.detector.DetectFromRequest(host, path)

	if packageIdentity != nil {
		// Check threat intelligence
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		intel, err := s.cache.Get(ctx, *packageIdentity)
		if err != nil {
			s.logger.Error("threat_intel_error", "Failed to get threat intelligence", map[string]interface{}{
				"package":    packageIdentity.String(),
				"error":      err.Error(),
				"request_id": requestID,
			})

			// Fail-open by default (configurable in production)
			// Allow the request to proceed
		} else {
			// Evaluate policy
			policyResult := s.policyEngine.Evaluate(policy.PolicyInput{
				Intel:           intel,
				PackageIdentity: *packageIdentity,
			})

			// Log the decision
			s.logger.LogPackageCheck(
				packageIdentity,
				intel,
				policyResult.Decision,
				s.policyEngine.GetMode(),
				s.policyEngine.IsCI(),
				requestID,
			)

			// Handle blocking
			if policyResult.ShouldBlock() {
				s.logger.Warn("package_blocked", policyResult.Reason, map[string]interface{}{
					"package":    packageIdentity.String(),
					"request_id": requestID,
				})

				// Return 403 Forbidden
				response := fmt.Sprintf(
					"HTTP/1.1 403 Forbidden\r\n"+
						"Content-Type: text/plain\r\n"+
						"Content-Length: %d\r\n"+
						"\r\n"+
						"%s",
					len(policyResult.Reason),
					policyResult.Reason,
				)
				clientConn.Write([]byte(response))
				return
			}

			// Handle warnings
			if policyResult.ShouldWarn() {
				s.logger.Warn("package_warning", policyResult.Reason, map[string]interface{}{
					"package":    packageIdentity.String(),
					"request_id": requestID,
				})
			}
		}
	}

	// Forward the request to the actual server
	s.forwardRequest(clientConn, req)
}

// forwardRequest forwards an HTTP request to the target server
func (s *Server) forwardRequest(clientConn net.Conn, req *http.Request) {
	// Ensure the URL is absolute
	if req.URL.Scheme == "" {
		if req.TLS != nil {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
	}

	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// Remove proxy-specific headers
	req.RequestURI = ""

	// Execute the request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("forward_error", "Failed to forward request", map[string]interface{}{
			"url":   req.URL.String(),
			"error": err.Error(),
		})

		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	// Write response to client
	resp.Write(clientConn)
}

// StartAndGetAddr starts the proxy server and returns the actual listening address
func (s *Server) StartAndGetAddr() (string, error) {
	if err := s.Start(); err != nil {
		return "", err
	}
	return s.Addr(), nil
}
