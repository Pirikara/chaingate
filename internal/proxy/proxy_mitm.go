package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/google/uuid"
	"github.com/tomoyayamashita/chain-gate/internal/cache"
	"github.com/tomoyayamashita/chain-gate/internal/ecosystem"
	"github.com/tomoyayamashita/chain-gate/internal/logger"
	"github.com/tomoyayamashita/chain-gate/internal/policy"
)

// Known package registry hosts that we should intercept
var knownRegistries = []string{
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"rubygems.org",
	"index.rubygems.org",
	"files.pythonhosted.org",
	"pypi.org",
	"pypi.python.org",
}

// MITMServer is a MITM proxy server
type MITMServer struct {
	addr         string
	listener     net.Listener
	proxy        *goproxy.ProxyHttpServer
	certManager  *CertManager
	detector     *ecosystem.Detector
	cache        *cache.ThreatIntelCache
	policyEngine *policy.Engine
	logger       *logger.Logger
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

// NewMITMServer creates a new MITM proxy server
func NewMITMServer(config Config, certDir string) (*MITMServer, error) {
	// Create certificate manager
	certManager, err := NewCertManager(certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert manager: %w", err)
	}

	// Create goproxy instance
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Set up MITM CA certificate
	// goproxy uses SetCA to configure the CA
	setCA := func() error {
		ca := tls.Certificate{
			Certificate: [][]byte{certManager.caCert.Raw},
			PrivateKey:  certManager.caKey,
			Leaf:        certManager.caCert,
		}
		goproxy.GoproxyCa = ca
		goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
		goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
		goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
		goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
		return nil
	}
	if err := setCA(); err != nil {
		return nil, err
	}

	server := &MITMServer{
		addr:         config.Addr,
		proxy:        proxy,
		certManager:  certManager,
		detector:     config.Detector,
		cache:        config.Cache,
		policyEngine: config.PolicyEngine,
		logger:       config.Logger,
		shutdownChan: make(chan struct{}),
	}

	// Set up request handler
	server.setupHandlers()

	return server, nil
}

// setupHandlers sets up the proxy handlers
func (s *MITMServer) setupHandlers() {
	// Handle HTTP requests
	s.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return s.handleHTTPRequest(req, ctx)
	})

	// Handle HTTPS CONNECT - only intercept known registries
	s.proxy.OnRequest(goproxy.ReqHostMatches(knownRegistryMatcher()...)).
		HandleConnect(goproxy.AlwaysMitm)

	// For other HTTPS connections, just tunnel
	s.proxy.OnRequest().HandleConnect(goproxy.AlwaysReject)

	// Handle HTTPS requests (after MITM)
	s.proxy.OnRequest(goproxy.ReqHostMatches(knownRegistryMatcher()...)).
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			return s.handleHTTPRequest(req, ctx)
		})
}

// knownRegistryMatcher creates matchers for known registries
func knownRegistryMatcher() []*regexp.Regexp {
	matchers := make([]*regexp.Regexp, 0, len(knownRegistries))
	for _, host := range knownRegistries {
		// Convert to regex pattern
		pattern := strings.ReplaceAll(host, ".", "\\.")
		pattern = "^" + pattern + "(:\\d+)?$"
		if re, err := regexp.Compile(pattern); err == nil {
			matchers = append(matchers, re)
		}
	}
	return matchers
}

// handleHTTPRequest handles both HTTP and HTTPS requests
func (s *MITMServer) handleHTTPRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	requestID := uuid.New().String()

	// Extract host and path
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	path := req.URL.Path
	if req.URL.RawQuery != "" {
		path = path + "?" + req.URL.RawQuery
	}

	// Try to detect package identity
	packageIdentity := s.detector.DetectFromRequest(host, path)

	if packageIdentity != nil {
		// Check threat intelligence
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		intel, err := s.cache.Get(ctxTimeout, *packageIdentity)
		if err != nil {
			s.logger.Error("threat_intel_error", "Failed to get threat intelligence", map[string]interface{}{
				"package":    packageIdentity.String(),
				"error":      err.Error(),
				"request_id": requestID,
			})
			// Fail-open: allow the request
			return req, nil
		}

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

			// Print user-friendly message to stderr
			fmt.Fprintf(os.Stderr, "\n"+
				"❌ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"+
				"   BLOCKED: Malicious package detected\n"+
				"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"+
				"   Package:  %s\n"+
				"   Version:  %s\n"+
				"   Reason:   %s\n"+
				"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n",
				packageIdentity.Name,
				packageIdentity.Version,
				policyResult.Reason,
			)

			// Create detailed response body
			responseBody := fmt.Sprintf(
				"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"+
				"Chain Gate: Package Blocked\n"+
				"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"+
				"Package:    %s@%s\n"+
				"Ecosystem:  %s\n"+
				"Reason:     %s\n\n"+
				"This package has been identified as malicious\n"+
				"and has been blocked by Chain Gate.\n\n"+
				"For more information, check the logs or visit:\n"+
				"  - OSSF malicious-packages: https://github.com/ossf/malicious-packages\n",
				packageIdentity.Name,
				packageIdentity.Version,
				packageIdentity.Ecosystem,
				policyResult.Reason,
			)

			// Return 403 Forbidden with detailed message
			return req, goproxy.NewResponse(req,
				goproxy.ContentTypeText,
				http.StatusForbidden,
				responseBody)
		}

		// Handle warnings
		if policyResult.ShouldWarn() {
			s.logger.Warn("package_warning", policyResult.Reason, map[string]interface{}{
				"package":    packageIdentity.String(),
				"request_id": requestID,
			})

			// Print user-friendly warning to stderr
			fmt.Fprintf(os.Stderr, "\n"+
				"⚠️  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"+
				"   WARNING: Vulnerable package detected\n"+
				"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"+
				"   Package:  %s\n"+
				"   Version:  %s\n"+
				"   Reason:   %s\n"+
				"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"+
				"   Installation will proceed, but please review this package.\n"+
				"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n",
				packageIdentity.Name,
				packageIdentity.Version,
				policyResult.Reason,
			)
		}
	}

	// Allow the request to proceed
	return req, nil
}

// Start starts the MITM proxy server
func (s *MITMServer) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	s.listener = listener
	s.logger.Info("proxy_start", fmt.Sprintf("MITM proxy server started on %s", s.addr), map[string]interface{}{
		"ca_cert": s.certManager.GetCACertPath(),
	})

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		http.Serve(listener, s.proxy)
	}()

	return nil
}

// Stop stops the MITM proxy server
func (s *MITMServer) Stop() error {
	close(s.shutdownChan)

	if s.listener != nil {
		s.listener.Close()
	}

	s.wg.Wait()

	s.logger.Info("proxy_stop", "MITM proxy server stopped", nil)
	return nil
}

// Addr returns the address the server is listening on
func (s *MITMServer) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

// StartAndGetAddr starts the server and returns the listening address
func (s *MITMServer) StartAndGetAddr() (string, error) {
	if err := s.Start(); err != nil {
		return "", err
	}
	return s.Addr(), nil
}

// GetCACertPath returns the path to the CA certificate
func (s *MITMServer) GetCACertPath() string {
	return s.certManager.GetCACertPath()
}
