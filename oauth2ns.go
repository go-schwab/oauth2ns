package oauth2ns

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/fatih/color"
	"golang.org/x/oauth2"
)

/*
Credit: @greytoc, https://gist.github.com/greytoc/3f8faf1ea50bfaf19d2ba5b31b66b1f6

Inspired by:
	https://github.com/int128/oauth2cli
	https://gist.github.com/marians/3b55318106df0e4e648158f1ffb43d38
	https://github.com/nmrshll/oauth2-noserver
	https://github.com/loomnetwork/oauth2-noserver
	https://github.com/paranoco/pnc/blob/main/oauth2ns/oauth2ns.go

To generate the TLS certificate:

openssl req -x509 -out localhost.crt -keyout localhost.key   -newkey rsa:2048 -nodes -sha256   -subj '/CN=localhost' -extensions EXT -config <( \
printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS.1:localhost,IP:127.0.0.1\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
*/

type AuthorizedClient struct {
	*http.Client
	Token *oauth2.Token
}

const (
	// IP is the ip of this machine that will be called back in the browser. It may not be a hostname.
	// If IP is not 127.0.0.1 DEVICE_NAME must be set. It can be any short string.
	IP          = "127.0.0.1"
	DEVICE_NAME = ""
	// seconds to wait before giving up on auth and exiting
	authTimeout                = 180
	oauthStateStringContextKey = 987
	PORT                       = 8888
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

type AuthenticateUserOption func(*AuthenticateUserFuncConfig) error
type AuthenticateUserFuncConfig struct {
	AuthCallHTTPParams url.Values
}

// Initiate an *AuthorizedClient with a given APPKEY, SECRET
// TODO: Include the user's given callback URL, as if someone wants to host off-prem they should be able to
// TODO: Investigate the previous statement, localhost might work for any implementation?
func Initiate(APPKEY, SECRET string) *AuthorizedClient {
	conf := &oauth2.Config{

		ClientID:     APPKEY, // Schwab App Key
		ClientSecret: SECRET, // Schwab App Secret

		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://api.schwabapi.com/v1/oauth/authorize",
			TokenURL: "https://api.schwabapi.com/v1/oauth/token",
		},
	}
	log.Println(color.CyanString("Authenticating User"))
	client, err := authenticateUser(conf)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(color.CyanString("User Authenticated"))
	return client
}

// Credit: https://gist.github.com/hyg/9c4afcd91fe24316cbf0
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		log.Fatalf("Unsupported platform.")
	}
	if err != nil {
		log.Fatalf("[err] %s", err.Error())
	}
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func WithAuthCallHTTPParams(values url.Values) AuthenticateUserOption {
	return func(conf *AuthenticateUserFuncConfig) error {
		conf.AuthCallHTTPParams = values
		return nil
	}
}

// authenticateUser starts the login process
func authenticateUser(oauthConfig *oauth2.Config, options ...AuthenticateUserOption) (*AuthorizedClient, error) {

	// read options
	var optionsConfig AuthenticateUserFuncConfig
	for _, processConfigFunc := range options {
		processConfigFunc(&optionsConfig)
	}

	// add transport for self-signed certificate to context
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	sslcli := &http.Client{Transport: tr}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, sslcli)

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	oauthConfig.RedirectURL = fmt.Sprintf("https://%s", IP)
	// Some random string, random for each request
	oauthStateString := randSeq(16)
	ctx = context.WithValue(ctx, oauthStateStringContextKey, oauthStateString)
	urlString := oauthConfig.AuthCodeURL(oauthStateString, oauth2.AccessTypeOnline)

	if optionsConfig.AuthCallHTTPParams != nil {
		parsedURL, err := url.Parse(urlString)
		if err != nil {
			return nil, fmt.Errorf("failed parsing url string")
		}
		params := parsedURL.Query()
		for key, value := range optionsConfig.AuthCallHTTPParams {
			params[key] = value
		}
		parsedURL.RawQuery = params.Encode()
		urlString = parsedURL.String()
	}

	if IP != "127.0.0.1" {
		urlString = fmt.Sprintf("%s&device_id=%s&device_name=%s", urlString, DEVICE_NAME, DEVICE_NAME)
	}

	clientChan, stopHTTPServerChan, cancelAuthentication := startHTTPServer(ctx, oauthConfig)
	log.Println(color.CyanString("You will now be taken to your browser for authentication or open the url below in a browser."))
	log.Println(color.CyanString(urlString))
	log.Println(color.CyanString("If you are opening the url manually on a different machine you will need to curl the result url on this machine manually."))
	time.Sleep(1000 * time.Millisecond)

	// open the browser
	openBrowser(urlString)
	time.Sleep(600 * time.Millisecond)

	// shutdown the server after timeout
	go func() {
		log.Printf("Authentication will be cancelled in %s seconds", strconv.Itoa(authTimeout))
		time.Sleep(authTimeout * time.Second)
		stopHTTPServerChan <- struct{}{}
	}()

	select {
	// wait for client on clientChan
	case client := <-clientChan:
		// After the callbackHandler returns a client, it's time to shutdown the server gracefully
		stopHTTPServerChan <- struct{}{}
		return client, nil

		// if authentication process is cancelled first return an error
	case <-cancelAuthentication:
		return nil, fmt.Errorf("authentication timed out and was cancelled")
	}

}

func startHTTPServer(ctx context.Context, conf *oauth2.Config) (clientChan chan *AuthorizedClient, stopHTTPServerChan chan struct{}, cancelAuthentication chan struct{}) {
	// init returns
	clientChan = make(chan *AuthorizedClient)
	stopHTTPServerChan = make(chan struct{})
	cancelAuthentication = make(chan struct{})

	http.HandleFunc("/", callbackHandler(ctx, conf, clientChan))

	srv := &http.Server{Addr: fmt.Sprintf("https://%s:%d", IP, PORT)}

	// handle server shutdown signal
	go func() {
		// wait for signal on stopHTTPServerChan
		<-stopHTTPServerChan
		log.Println("Shutting down server...")

		// give it 5 sec to shutdown gracefully, else quit program
		d := time.Now().Add(5 * time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), d)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf(color.RedString("Auth server could not shutdown gracefully: %v"), err)
		}

		// after server is shutdown, quit program
		cancelAuthentication <- struct{}{}
	}()

	// handle callback request
	go func() {
		if err := srv.ListenAndServeTLS("localhost.crt", "localhost.key"); err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
		fmt.Println("Server gracefully stopped")
	}()

	return clientChan, stopHTTPServerChan, cancelAuthentication
}

func callbackHandler(ctx context.Context, oauthConfig *oauth2.Config, clientChan chan *AuthorizedClient) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		requestStateString := ctx.Value(oauthStateStringContextKey).(string)
		responseStateString := r.FormValue("state")
		if responseStateString != requestStateString {
			fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", requestStateString, responseStateString)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		code := r.FormValue("code")
		token, err := oauthConfig.Exchange(ctx, code)
		if err != nil {
			fmt.Printf("oauthoauthConfig.Exchange() failed with '%s'\n", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		// The HTTP Client returned by oauthConfig.Client will refresh the token as necessary
		client := &AuthorizedClient{
			oauthConfig.Client(ctx, token),
			token,
		}
		// show success page
		successPage := `
		<html>
		<div style="height:100px; width:100%!; display:flex; flex-direction: column; justify-content: center; align-items:center; background-color:#2ecc71; color:white; font-size:22"><div>Success!</div></div>
		<p style="margin-top:20px; font-size:18; text-align:center">You are authenticated. Close this window to continue.</p>
		</html>
		`
		fmt.Fprintf(w, successPage)
		// quitSignalChan <- quitSignal
		clientChan <- client
	}
}
