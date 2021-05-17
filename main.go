package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	MY_SOCK_DEFAULT_PATH             = "/run/dim.sock"
	DOCKER_SOCK_DEFAULT_PATH         = "/run/docker.sock"
	READ_BUFFER_SIZE                 = 64 * 1024
	WRITE_BUFFER_SIZE                = 64 * 1024
	REGEXP_POST_HEADER_NEW_CONTAINER = `^POST /v\d+\.\d+/containers/create HTTP/\d`
	REGEXP_EXTRACT_JSON_STRUCTURE    = `(?m)^.*\n(\{.*\}).*$`
	REGEXP_CONTENT_LENGTH_CORRECTION = `Content-Length: (\d+)`
)

type RegularExpressions struct {
	PostHeader    *regexp.Regexp
	ExtractJson   *regexp.Regexp
	ContentLength *regexp.Regexp
}

func check_if_interception_needed(client_wrote string, bytelen int, re *RegularExpressions) ([]byte, int) {
	if re.PostHeader.MatchString(client_wrote) {
		log.Debugf("We found a message to intercept: %s\n", client_wrote)
		json_string_holder := re.ExtractJson.FindStringSubmatch(client_wrote)
		if len(json_string_holder) == 2 {
			log.Debugf("JSON string: %s\n", json_string_holder[1])
			content_length_holder := re.ContentLength.FindStringSubmatch(client_wrote)
			if len(content_length_holder) >= 2 {
				oldlen, err := strconv.Atoi(content_length_holder[1])
				if err == nil {
					// this should be done better:
					new_userns_mode := strings.Replace(client_wrote, `"UsernsMode":""`, `"UsernsMode":"host"`, -1)
					if len(new_userns_mode) != len(client_wrote) {
						conten_length_replaced := re.ContentLength.ReplaceAllString(new_userns_mode, fmt.Sprintf("Content-Length: %d", oldlen+4))
						log.Debugf("Returning intercepted and corrected message: %s\n", conten_length_replaced)
						return []byte(conten_length_replaced), bytelen + 4
					} else {
						log.Debugf("Userns Mode is not empty")
					}
				} else {
					log.Debugf("Old content length was not an integer: %s\n", content_length_holder[1])
				}
			} else {
				log.Debugf("Did not find the Conten-Length header: %q\n", content_length_holder)
			}
		} else {
			log.Debugf("The JSON string holder didn't contain 2 elements: %q\n", json_string_holder)
		}
	}
	return []byte(client_wrote), bytelen
}

func check_error_to_close_conn(formaat string, err error, client, docker_sock *net.Conn) int {
	if err != nil {
		err_str := fmt.Sprintf("%s", err)
		if err_str != "EOF" && !strings.HasSuffix(err_str, "use of closed network connection") {
			log.Errorf(formaat, err)
		}
		if client != nil {
			(*client).Close()
		}
		if docker_sock != nil {
			(*docker_sock).Close()
		}
		return -1
	} else {
		return 0
	}
}

func client_read_thread(client, docker_sock *net.Conn, re *RegularExpressions) {
	var buffer []byte = make([]byte, READ_BUFFER_SIZE)
	for {
		rn, err := (*client).Read(buffer)
		if check_error_to_close_conn("Unable to read from client connection: %s\n", err, client, docker_sock) < 0 {
			return
		}
		intercepted_data, rn := check_if_interception_needed(string(buffer[:rn]), rn, re)
		wn, err := (*docker_sock).Write(intercepted_data)
		if check_error_to_close_conn("Unable to write to Docker connection: %s\n", err, client, docker_sock) < 0 {
			return
		}
		if wn != rn {
			log.Errorf("Bytes written to Docker differ from read from client: %d != %d\n", wn, rn)
			(*client).Close()
			(*docker_sock).Close()
			return
		}
	}
}

func client_write_thread(client, docker_sock *net.Conn) {
	var buffer []byte = make([]byte, WRITE_BUFFER_SIZE)
	for {
		rn, err := (*docker_sock).Read(buffer)
		if check_error_to_close_conn("Unable to read from Docker connection: %s\n", err, client, docker_sock) < 0 {
			return
		}
		wn, err := (*client).Write(buffer[:rn])
		if check_error_to_close_conn("Unable to write to client connection: %s\n", err, client, docker_sock) < 0 {
			return
		}
		if wn != rn {
			log.Errorf("Bytes written to client differ from read from Docker: %d != %d\n", wn, rn)
			(*client).Close()
			(*docker_sock).Close()
			return
		}
	}
}

func main() {
	do_debug := flag.Bool("debug", false, "Set this flag to true in order to see debugging messages")
	flag.Parse()
	if *do_debug {
		log.SetLevel(log.DebugLevel)
	}

	re := regexp.MustCompile(REGEXP_POST_HEADER_NEW_CONTAINER)
	re2 := regexp.MustCompile(REGEXP_EXTRACT_JSON_STRUCTURE)
	re3 := regexp.MustCompile(REGEXP_CONTENT_LENGTH_CORRECTION)
	regexpes := &RegularExpressions{PostHeader: re, ExtractJson: re2, ContentLength: re3}

	listener, err := net.Listen("unix", MY_SOCK_DEFAULT_PATH)
	if err != nil {
		log.Fatalf("Unable to start socket listener at %s: %s\n", MY_SOCK_DEFAULT_PATH, err)
	}
	log.Debugf("Listener at %s started\n", MY_SOCK_DEFAULT_PATH)

	interrupt_channel := make(chan os.Signal, 1)
	signal.Notify(interrupt_channel, os.Interrupt)
	go func() {
		for range interrupt_channel {
			listener.Close()
		}
	}()

	for {
		client_conn, err := listener.Accept()
		if check_error_to_close_conn("Unable to accept new connection: %s\n", err, nil, nil) < 0 {
			return
		}
		log.Debugf("Accepted new connection from: %s\n", client_conn.RemoteAddr())
		docker_sock, err := net.Dial("unix", DOCKER_SOCK_DEFAULT_PATH)
		if err != nil {
			client_conn.Close()
			log.Errorf("Unable to connect to Docker socket at %s: %s\n", DOCKER_SOCK_DEFAULT_PATH, err)
		} else {
			log.Debugf("Successfully opened a new Docker connection from client connection at: %s\n", client_conn.RemoteAddr())
			go client_read_thread(&client_conn, &docker_sock, regexpes)
			go client_write_thread(&client_conn, &docker_sock)
		}
	}
}
