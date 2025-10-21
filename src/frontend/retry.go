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
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxRetries = 3
	retryDelay = 100 * time.Millisecond
)

// shouldRetry checks if the error is retryable
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	
	// Retry on transient errors (including injected ones)
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted:
		return true
	default:
		return false
	}
}

// retryUnaryClientInterceptor adds retry logic to gRPC calls
func retryUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		var err error
		
		for attempt := 0; attempt <= maxRetries; attempt++ {
			err = invoker(ctx, method, req, reply, cc, opts...)
			
			if err == nil {
				return nil
			}
			
			if !shouldRetry(err) {
				return err
			}
			
			if attempt < maxRetries {
				log.Warnf("[RETRY] Attempt %d/%d failed for %s: %v", attempt+1, maxRetries+1, method, err)
				time.Sleep(retryDelay * time.Duration(attempt+1))
			}
		}
		
		log.Errorf("[RETRY] All %d attempts failed for %s", maxRetries+1, method)
		return err
	}
}
