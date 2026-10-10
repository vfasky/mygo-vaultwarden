// SPDX-License-Identifier: GPL-3.0-only
// Test-only SMTP sink. It never relays mail and accepts only example.invalid.
// Package main provides the test invitation SMTP receiver.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:1025")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go receive(conn)
	}
}

func receive(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := textproto.NewReader(bufio.NewReader(conn))
	reply := func(line string) { _, _ = fmt.Fprint(conn, line+"\r\n") }
	reply("220 isolated fixture")
	var recipients []string
	for {
		line, err := reader.ReadLine()
		if err != nil {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO "), strings.HasPrefix(upper, "HELO "):
			reply("250 isolated fixture")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			recipients = nil
			reply("250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			email := strings.Trim(strings.TrimSpace(line[len("RCPT TO:"):]), "<>")
			if !strings.HasSuffix(email, "@example.invalid") || strings.ContainsAny(email, " \t\r\n") {
				reply("550 fixture recipients only")
				continue
			}
			recipients = append(recipients, email)
			reply("250 OK")
		case upper == "DATA":
			if len(recipients) == 0 {
				reply("503 recipient required")
				continue
			}
			reply("354 continue")
			data, err := io.ReadAll(io.LimitReader(reader.DotReader(), (1<<20)+1))
			if err != nil || len(data) > 1<<20 {
				reply("552 too large")
				return
			}
			message, _ := json.Marshal(struct {
				Recipients []string
				Data       string
			}{recipients, string(data)})
			file, err := os.CreateTemp("/fixture/mail", "message-")
			if err != nil {
				reply("451 spool unavailable")
				return
			}
			_ = file.Chmod(0600)
			_, writeErr := file.Write(message)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				reply("451 spool failed")
				return
			}
			reply("250 stored")
			recipients = nil
		case upper == "RSET":
			recipients = nil
			reply("250 OK")
		case upper == "QUIT":
			reply("221 bye")
			return
		case upper == "NOOP":
			reply("250 OK")
		default:
			reply("502 unsupported")
		}
	}
}
