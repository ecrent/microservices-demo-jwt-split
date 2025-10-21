// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorInjectionConfig holds configuration for error injection
type ErrorInjectionConfig struct {
	Enabled       bool
	ErrorRate     float64 // 0.0 to 1.0 (0% to 100%)
	ErrorType     string  // "unavailable", "timeout", "internal", "deadline_exceeded", "random"
	TargetService string  // "CartService", "all", or comma-separated list
}

var (
	errorInjectionConfig *ErrorInjectionConfig
	randSource           *rand.Rand
	errInjLog            *logrus.Logger // Dedicated logger for error injection
)

func init() {
	// Initialize random source with current time for true randomness
	randSource = rand.New(rand.NewSource(time.Now().UnixNano()))
	// Don't load config here - will be done explicitly after logger is ready
}

// InitErrorInjection initializes error injection with the provided logger
func InitErrorInjection(logger *logrus.Logger) {
	errInjLog = logger
	errorInjectionConfig = loadErrorInjectionConfig()
}

// loadErrorInjectionConfig reads error injection settings from environment variables
func loadErrorInjectionConfig() *ErrorInjectionConfig {
	config := &ErrorInjectionConfig{
		Enabled:       false,
		ErrorRate:     0.0,
		ErrorType:     "unavailable",
		TargetService: "CartService",
	}

	// Check if error injection is enabled
	if os.Getenv("ENABLE_ERROR_INJECTION") == "true" {
		config.Enabled = true
		errInjLog.Info("[ERROR-INJECTION] Error injection is ENABLED")
	} else {
		errInjLog.Info("[ERROR-INJECTION] Error injection is DISABLED")
		return config
	}

	// Parse error rate (default 10% if not specified)
	if rateStr := os.Getenv("ERROR_INJECTION_RATE"); rateStr != "" {
		if rate, err := strconv.ParseFloat(rateStr, 64); err == nil {
			if rate >= 0.0 && rate <= 1.0 {
				config.ErrorRate = rate
			} else {
				errInjLog.Warnf("[ERROR-INJECTION] Invalid error rate %f, using default 0.1", rate)
				config.ErrorRate = 0.1
			}
		} else {
			errInjLog.Warnf("[ERROR-INJECTION] Failed to parse error rate: %v, using default 0.1", err)
			config.ErrorRate = 0.1
		}
	} else {
		config.ErrorRate = 0.1 // Default 10%
	}

	// Parse error type
	if errType := os.Getenv("ERROR_INJECTION_TYPE"); errType != "" {
		config.ErrorType = strings.ToLower(errType)
	}

	// Parse target service
	if target := os.Getenv("ERROR_INJECTION_TARGET"); target != "" {
		config.TargetService = target
	}

	errInjLog.Infof("[ERROR-INJECTION] Configuration loaded - Rate: %.1f%%, Type: %s, Target: %s",
		config.ErrorRate*100, config.ErrorType, config.TargetService)

	return config
}

// shouldInjectError determines if an error should be injected for this call
func shouldInjectError(method string) bool {
	if !errorInjectionConfig.Enabled {
		return false
	}

	// Check if this service is targeted
	if !isTargetService(method) {
		return false
	}

	// Random chance based on error rate
	return randSource.Float64() < errorInjectionConfig.ErrorRate
}

// isTargetService checks if the method belongs to a targeted service
func isTargetService(method string) bool {
	target := errorInjectionConfig.TargetService

	// If target is "all", inject errors for all services
	if target == "all" {
		return true
	}

	// Check if method matches any of the comma-separated targets
	targets := strings.Split(target, ",")
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if strings.Contains(method, t) {
			return true
		}
	}

	return false
}

// getInjectedError returns the appropriate gRPC error based on configuration
func getInjectedError(method string) error {
	errorType := errorInjectionConfig.ErrorType

	// If random error type, pick one randomly
	if errorType == "random" {
		errorTypes := []string{"unavailable", "timeout", "internal", "deadline_exceeded"}
		errorType = errorTypes[randSource.Intn(len(errorTypes))]
	}

	var err error
	switch errorType {
	case "unavailable":
		err = status.Error(codes.Unavailable, "INJECTED_ERROR: simulated service unavailable (error injection)")
	case "timeout":
		// Simulate timeout by sleeping then returning deadline exceeded
		time.Sleep(100 * time.Millisecond)
		err = status.Error(codes.DeadlineExceeded, "INJECTED_ERROR: simulated timeout (error injection)")
	case "internal":
		err = status.Error(codes.Internal, "INJECTED_ERROR: simulated internal error (error injection)")
	case "deadline_exceeded":
		err = status.Error(codes.DeadlineExceeded, "INJECTED_ERROR: simulated deadline exceeded (error injection)")
	case "connection_refused":
		err = status.Error(codes.Unavailable, "INJECTED_ERROR: simulated connection refused (error injection)")
	case "packet_loss":
		err = status.Error(codes.Unavailable, "INJECTED_ERROR: simulated packet loss (error injection)")
	default:
		err = status.Error(codes.Unavailable, fmt.Sprintf("INJECTED_ERROR: simulated error type: %s (error injection)", errorType))
	}

	errInjLog.Warnf("[ERROR-INJECTION] 🔴 Injecting %s error for method: %s", errorType, method)
	return err
}

// errorInjectionUnaryClientInterceptor injects errors into unary gRPC calls
func errorInjectionUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		// Check if we should inject an error
		if shouldInjectError(method) {
			return getInjectedError(method)
		}

		// No error injection, proceed normally
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// errorInjectionStreamClientInterceptor injects errors into streaming gRPC calls
func errorInjectionStreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		// Check if we should inject an error
		if shouldInjectError(method) {
			return nil, getInjectedError(method)
		}

		// No error injection, proceed normally
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// GetErrorInjectionStats returns current error injection statistics (for monitoring)
func GetErrorInjectionStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":        errorInjectionConfig.Enabled,
		"error_rate":     errorInjectionConfig.ErrorRate,
		"error_type":     errorInjectionConfig.ErrorType,
		"target_service": errorInjectionConfig.TargetService,
	}
}
