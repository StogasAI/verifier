package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	stogas "github.com/StogasAI/verifier/go"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

func client(baseURL, apiKey string) (openai.Client, *http.Client) {
	network := http.DefaultTransport.(*http.Transport).Clone()
	network.Proxy = nil // The managed transport URL is local and must bypass proxies.
	httpClient := &http.Client{
		Transport:     network,
		Timeout:       45 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are disabled") },
	}
	return openai.NewClient(
		option.WithAPIKey(apiKey), option.WithBaseURL(baseURL),
		option.WithMaxRetries(0), option.WithHTTPClient(httpClient),
	), httpClient
}

func run(ctx context.Context) error {
	key, model := os.Getenv("STOGAS_API_KEY"), os.Getenv("STOGAS_MODEL")
	if key == "" || model == "" {
		return errors.New("STOGAS_API_KEY and STOGAS_MODEL are required")
	}
	transport, err := stogas.NewTransport(stogas.TransportOptions{})
	if err != nil {
		return err
	}
	defer transport.Close()
	baseURL, err := transport.BaseURL()
	if err != nil {
		return err
	}
	api, network := client(baseURL, key)
	defer network.CloseIdleConnections()
	stream := api.Chat.Completions.NewStreaming(ctx, openai.ChatCompletionNewParams{
		Model:    model,
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Say hello in one sentence.")},
	})
	defer stream.Close()
	for stream.Next() {
		for _, choice := range stream.Current().Choices {
			fmt.Print(choice.Delta.Content)
		}
	}
	if err := stream.Err(); err != nil {
		return err
	}
	fmt.Println()
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
