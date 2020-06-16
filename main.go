// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

var (
	vaultAddr     string
	gcsBucketName string
	httpClient    http.Client

	githubOrganization string
	githubAdminUser    string

	kmsService *cloudkms.Service
	kmsKeyId   string

	storageClient *storage.Client

	userAgent = fmt.Sprintf("vault-setup-github/1.0.0 (%s)", runtime.Version())
)

// AuthGithubConfigRequest holds a Github Config request
type AuthGithubConfigRequest struct {
	organization string `json:"organization"`
}

// AuthGithubMapUser holds a Github Config request
type AuthGithubMapUser struct {
	value string `json:"value"`
}

// AuthMethodsResponse result of auth method request
type AuthMethodsResponse struct {
	Github interface{} `json:"github/"`
}

// ActivateAuthRequest holds a sys auth request
type ActivateAuthRequest struct {
	description string `json:"description"`
	typeofAuth  string `json:"type"`
}

func main() {
	log.Println("Starting the vault-setup-github service...")

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	vaultInsecureSkipVerify := boolFromEnv("VAULT_SKIP_VERIFY", false)

	githubOrganization = os.Getenv("GITHUB_ORGANIZATION")

	githubAdminUser = os.Getenv("GITHUB_ADMIN_USER")

	gcsBucketName = os.Getenv("GCS_BUCKET_NAME")
	if gcsBucketName == "" {
		log.Fatal("GCS_BUCKET_NAME must be set and not empty")
	}

	kmsKeyId = os.Getenv("KMS_KEY_ID")
	if kmsKeyId == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
	}

	kmsCtx, kmsCtxCancel := context.WithCancel(context.Background())
	defer kmsCtxCancel()
	kmsClient, err := google.DefaultClient(kmsCtx, "https://www.googleapis.com/auth/cloudkms")
	if err != nil {
		log.Println(err)
		return
	}

	kmsService, err = cloudkms.New(kmsClient)
	if err != nil {
		log.Println(err)
		return
	}
	kmsService.UserAgent = userAgent

	storageCtx, storageCtxCancel := context.WithCancel(context.Background())
	defer storageCtxCancel()
	storageClient, err = storage.NewClient(storageCtx,
		option.WithUserAgent(userAgent),
		option.WithScopes(storage.ScopeReadWrite),
	)
	if err != nil {
		log.Fatal(err)
	}

	httpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: vaultInsecureSkipVerify,
			},
		},
	}

	signalCh := make(chan os.Signal)
	signal.Notify(signalCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
	)

	stop := func() {
		log.Printf("Shutting down")
		kmsCtxCancel()
		storageCtxCancel()
		os.Exit(0)
	}

	response, err := httpClient.Head(vaultAddr + "/v1/sys/health")

	if response != nil && response.Body != nil {
		response.Body.Close()
	}

	if err != nil {
		log.Println(err)
		stop()
	}

	switch response.StatusCode {
	case 200:
		log.Println("Vault is initialized and unsealed.")
		token, err := getRootToken()
		if err != nil {
			log.Println(err)
			stop()
		}

		isActivated, err := isGithubActivated(token)
		if err != nil {
			log.Println(err)
			stop()
		}

		if !isActivated {
			configureGithubOrganization(token)
			if githubAdminUser != "" {
				addGithubAdmin(token)
			}
		} else {
			stop()
		}
	default:
		log.Printf("Vault is in an unknown state. Status code: %d", response.StatusCode)
	}

	stop()
}

func getRootToken() (string, error) {
	bucket := storageClient.Bucket(gcsBucketName)

	ctx := context.Background()
	rootTokenEnc, err := bucket.Object("root-token.enc").NewReader(ctx)
	if err != nil {
		return "", err
	}

	defer rootTokenEnc.Close()

	rootTokenData, err := ioutil.ReadAll(rootTokenEnc)
	if err != nil {
		return "", err
	}

	rootTokenDecryptRequest := &cloudkms.DecryptRequest{
		Ciphertext: string(rootTokenData),
	}

	rootTokenDecryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(kmsKeyId, rootTokenDecryptRequest).Do()
	if err != nil {
		return "", err
	}

	rootToken, err := base64.StdEncoding.DecodeString(rootTokenDecryptResponse.Plaintext)
	if err != nil {
		return "", err
	}

	return string(rootToken), nil
}

func isGithubActivated(rootToken string) (bool, error) {
	request, err := http.NewRequest("GET", vaultAddr+"/sys/auth", nil)
	request.Header.Add("X-Vault-Token", string(rootToken))

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}

	defer response.Body.Close()

	authMethodsResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var authMethods AuthMethodsResponse

	if err := json.Unmarshal(authMethodsResponseBody, &authMethods); err != nil {
		return false, err
	}

	if authMethods.Github != nil {
		return true, nil
	} else {
		return false, nil
	}
}

func configureGithubOrganization(rootToken string) {

	activateAuthRequest := ActivateAuthRequest{
		description: "Automatically added by vault-setup-github",
		typeofAuth:  "github",
	}

	activateAuthRequestData, err := json.Marshal(&activateAuthRequest)
	if err != nil {
		log.Println(err)
		return
	}

	rard := bytes.NewReader(activateAuthRequestData)
	actRequest, err := http.NewRequest("POST", vaultAddr+"/v1/sys/auth/github", rard)
	actRequest.Header.Add("X-Vault-Token", string(rootToken))

	if err != nil {
		log.Println(err)
		return
	}

	httpClient.Do(actRequest)

	initRequest := AuthGithubConfigRequest{
		organization: githubOrganization,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	r := bytes.NewReader(initRequestData)
	request, err := http.NewRequest("POST", vaultAddr+"/v1/auth/github/config", r)
	request.Header.Add("X-Vault-Token", string(rootToken))

	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request)

	if err != nil {
		log.Println(err)
		return
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		log.Println("Was not able to configure Github")
		return
	}
}

func addGithubAdmin(rootToken string) {

	initRequest := AuthGithubMapUser{
		value: "root",
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	r := bytes.NewReader(initRequestData)
	request, err := http.NewRequest("POST", vaultAddr+"/v1/auth/github/map/users/"+githubAdminUser, r)
	request.Header.Add("X-Vault-Token", string(rootToken))

	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request)

	if err != nil {
		log.Println(err)
		return
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		log.Println("Was not able to add administrator user to root policy")
		return
	}
}

func boolFromEnv(env string, def bool) bool {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return b
}

func intFromEnv(env string, def int) int {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return i
}

func durFromEnv(env string, def time.Duration) time.Duration {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	r := val[len(val)-1]
	if r >= '0' || r <= '9' {
		val = val + "s" // assume seconds
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Fatalf("failed to parse %q: %s", env, err)
	}
	return d
}
