package main

import (
	"context"
	"encoding/json"
	"fmt"
	"identityserver4_golang_resourceserver/id4rs"
	"log"
	"net/http"

	"github.com/rs/cors"
)

const issuer = "http://localhost:7000"
const audience = "goapi"

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", homeHandler)
	mux.Handle("/api/messages", authMiddleWare(http.HandlerFunc(protectedAPIHandler)))

	//cors
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"Content-Type", "authorization"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowCredentials: true,
	})

	http.ListenAndServe(":8000", c.Handler(mux))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, this is IdentityServer4 golang resource server sample")
}

func protectedAPIHandler(w http.ResponseWriter, r *http.Request) {
	userInfo := getContextUserInfo(r.Context(), contextKey("userInfo"))

	userInfoJSON, _ := json.Marshal(userInfo)

	fmt.Fprintf(w, "Protected Api, userInfo: %v", string(userInfoJSON))
}

func authMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("auth middleware started")

		bearerToken, err := id4rs.GetBearerToken(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "400 - Bad Request")
			return
		}

		ctx := r.Context()
		authVerifier, err := id4rs.NewAuthVerifier(ctx, issuer, audience)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "500 - Server Error")
			return
		}

		err = authVerifier.Verify(bearerToken)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "401 - You are not authorized for this request, %v", err)
			return
		}

		userInfo, err := authVerifier.GetUserInfo(bearerToken)
		fmt.Println(userInfo)

		userClaims, err := id4rs.GetUserClaims(userInfo)
		fmt.Println(userClaims)

		ctx = context.WithValue(ctx, contextKey("userInfo"), userClaims)

		next.ServeHTTP(w, r.WithContext(ctx))
		log.Println("auth middleware finished")
	})
}

func getContextUserInfo(ctx context.Context, k contextKey) interface{} {
	if v := ctx.Value(k); v != nil {
		return v
	}
	return nil
}

type contextKey string
