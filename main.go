// A tiny CLI tool to automate the authentication and keepalive requests for IIT Kanpur's Fortinet captive portal.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/term"
)

const maxRetries = 5

// Stores the current login status along with authentication and keepalive urls.
type state struct {
	loggedIn     bool
	authURL      string
	keepaliveURL string
}

// Checks whether the user is logged in.
//
// If any error occurs then it is returned while state remains unchanged. Otherwise `state.loggedIn` is set to the
// appropriate value and `nil` is returned. If user is not logged in then `state.authURL` is also set.
func check(checkURL string, state *state) error {
	resp, err := http.Get(checkURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("empty response body")
	}

	re := regexp.MustCompile(`^<html><body><script language="JavaScript">window\.location="(https:\/\/gateway\.iitk\.ac\.in:\d+\/fgtauth\?[a-f\d]+)";<\/script><\/body><\/html>$`)
	match := re.FindSubmatch(body)

	// There's no good way to know if regex is unmatched because fortinet changed the template or if we actually get the
	// requested webpage. For now, we assume that if regex does not match user is logged in. Definitely need to come up
	// with a better strategy.
	if match == nil {
		state.loggedIn = true
		return nil
	}

	state.authURL = string(match[1])
	return nil
}

// Authenticates the user with the supplied username and password.
//
// If any error occurs it is returned and state is unchanged. Otherwise `state.loggedIn` is set to `true` and
// `state.keepaliveURL` is set to the extracted keepalive url and `nil` is returned.
func auth(username string, password string, state *state) error {
	resp, err := http.Get(state.authURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	re := regexp.MustCompile(`<input type="hidden" name="magic" value="([a-f\d]+)">`)
	match := re.FindSubmatch(body)
	if match == nil {
		return fmt.Errorf("magic value not found")
	}

	// Start a new block since we use reuse `body` and would like to defer the close operation again.
	{
		values := url.Values{}
		values.Set("username", username)
		values.Set("password", password)
		values.Set("magic", string(match[1]))
		resp, err = http.PostForm(state.authURL[:8+strings.Index(state.authURL[8:], "/")], values)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		// Probably should relax the regex matching a bit here and just look for keepalive url.
		re = regexp.MustCompile(`<html><body><script language="JavaScript">window\.location="(https:\/\/gateway\.iitk\.ac\.in:\d+\/keepalive\?[a-f\d]+)";<\/script><\/body><\/html>`)
		match = re.FindSubmatch(body)
		if match == nil {
			return fmt.Errorf("keepalive url not found")
		}

		state.loggedIn = true
		state.keepaliveURL = string(match[1])
		return nil
	}
}

// Sends a keepalive request.
//
// If any error occurs it is returned, otherwise returns `nil`. Does not modify `state`.
func keepalive(state *state) error {
	resp, err := http.Get(state.keepaliveURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("response status: %v", resp.Status)
	}

	return nil
}

func main() {
	help := pflag.BoolP("help", "h", false, "Print this help")
	username := pflag.StringP("username", "u", "", "Username")
	password := pflag.StringP("password", "p", "", "Password")
	checkURL := pflag.String("url", "http://google.com", "URL to use for checking connection")
	retryTime := pflag.Int64("retry_time", 1, "Seconds to wait before retrying operations")
	checkTime := pflag.Int64("check_time", 10, "Seconds to wait before re-checking state")
	keepaliveTime := pflag.Int64("keepalive_time", 60, "Seconds to wait before sending keepalive request")
	pflag.Parse()

	if *help {
		fmt.Println("Usage: fortiauth [options]")
		fmt.Println()
		fmt.Println("Options:")
		pflag.PrintDefaults()
		os.Exit(0)
	}

	if *username == "" {
		fmt.Print("username: ")
		_, err := fmt.Scanln(username)
		if err != nil {
			fmt.Println("Failed to read username. Exiting program")
			os.Exit(1)
		}
	}
	if *password == "" {
		fmt.Print("password: ")
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Println("Failed to read password. Exiting program")
			os.Exit(1)
		}
		*password = string(data)
	}

	state := new(state)
	state.loggedIn = false

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs

		if state.loggedIn {
			log.Println("Logging out")
			resp, err := http.Get(strings.Replace(state.keepaliveURL, "keepalive", "logout", 1))
			if err != nil {
				log.Fatalf("Failed to log out: %v. Exiting program\n", err)
			}
			if resp.StatusCode != http.StatusOK {
				log.Fatalf("Failed to log out: response status %v. Exiting program\n", resp.Status)
			}
			log.Println("Successfully logged out. Exiting program")
			os.Exit(0)
		}
	}()

	retryCount := 0
	var err error
	for {
		sleepTime := *retryTime
		if !state.loggedIn && state.authURL == "" {
			if retryCount == 0 {
				log.Printf("Checking state against url: %v\n", *checkURL)
			} else {
				log.Printf("Checking state against url: %v (Retrying %v/%v)\n", *checkURL, retryCount, maxRetries)
			}
			err = check(*checkURL, state)
			if err != nil {
				log.Printf("Failed to check state: %v\n", err)
				retryCount++
			} else {
				retryCount = 0
			}

			if retryCount > maxRetries {
				log.Fatalln("Maximum number of retries exceeded while trying to check state. Exiting program")
			}
		} else if !state.loggedIn {
			if retryCount == 0 {
				log.Printf("Attempting to login. Authentication url: %v\n", state.authURL)
			} else {
				log.Printf("Attempting to login. Authentication url: %v (Retrying %v/%v)\n", state.authURL, retryCount, maxRetries)
			}
			err = auth(*username, *password, state)
			if err != nil {
				log.Printf("Failed to authenticate: %v\n", err)
				retryCount++
			} else {
				log.Println("Successfully logged in")
				retryCount = 0
			}

			if retryCount > maxRetries {
				log.Fatalln("Maximum number of retries exceeded while trying to log in. Exiting program")
			}
		} else if state.keepaliveURL != "" {
			if retryCount == 0 {
				log.Printf("Sending keepalive request. Keepalive url: %v\n", state.keepaliveURL)
			} else {
				log.Printf("Sending keepalive request. Keepalive url: %v (Retrying %v/%v)\n", state.keepaliveURL, retryCount, maxRetries)
			}
			err = keepalive(state)
			if err != nil {
				log.Printf("Failed to send keepalive: %v\n", err)
				retryCount++
			} else {
				log.Printf("Keeping alive. Sleeping for %v seconds\n", *keepaliveTime)
				retryCount = 0
				sleepTime = *keepaliveTime
			}

			if retryCount > maxRetries {
				log.Println("Maximum number of retries exceeded while trying to keepalive. Clearing keepalive url")
				retryCount = 0
				state.keepaliveURL = ""
			}
		} else {
			log.Printf("Already logged in. No keepalive url. Sleeping for %v seconds\n", *checkTime)
			retryCount = 0
			state.loggedIn = false
			sleepTime = *checkTime
		}

		time.Sleep(time.Duration(sleepTime) * time.Second)
	}
}
