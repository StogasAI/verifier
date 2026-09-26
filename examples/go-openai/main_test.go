package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/openai-go/v3"
)

func TestRequestObjectsDoNotRetryOrFollowRedirects(t *testing.T) {
	for _, status := range []int{200, 307, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer example-key" {
					t.Errorf("unexpected request path or credentials")
				}
				var request struct {
					Model    string
					Messages []struct{ Role, Content string }
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if request.Model != "example/model" || len(request.Messages) != 1 || request.Messages[0].Content != "hello" {
					t.Errorf("unexpected request: %+v", request)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Location", "/must-not-follow")
				w.WriteHeader(status)
				if status == 200 {
					fmt.Fprint(w, `{"id":"chat-1","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}]}`)
				} else {
					fmt.Fprint(w, `{"error":{"message":"Unavailable","type":"server_error"}}`)
				}
			}))
			defer server.Close()
			api, network := client(server.URL+"/v1/", "example-key")
			defer network.CloseIdleConnections()
			result, err := api.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
				Model: "example/model", Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("hello")},
			})
			if status == 200 {
				if err != nil {
					t.Fatal(err)
				}
				if result.Choices[0].Message.Content != "Hello" {
					t.Fatal("lost response")
				}
			} else if err == nil {
				t.Fatal("accepted error or redirect")
			}
			if calls.Load() != 1 {
				t.Fatalf("inference dispatched %d times", calls.Load())
			}
		})
	}
}

func TestCancellationPropagatesThroughOpenAIStream(t *testing.T) {
	ended := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"id\":\"chat-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(ended)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	api, network := client(server.URL+"/v1/", "example-key")
	defer network.CloseIdleConnections()
	stream := api.Chat.Completions.NewStreaming(ctx, openai.ChatCompletionNewParams{
		Model: "example/model", Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("hello")},
	})
	defer stream.Close()
	if !stream.Next() {
		t.Fatal(stream.Err())
	}
	cancel()
	if stream.Next() || stream.Err() == nil {
		t.Fatal("cancellation became successful completion")
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled stream retained the connection")
	}
}
