package main

import (
	"context"
)

type contextKey string

const userContextKey contextKey = "user"

func setUserContext(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, userContextKey, username)
}

func getUserFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(userContextKey).(string)
	return username, ok
} 