// Copyright 2016-2019 DutchSec (https://dutchsec.com/)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package smtp

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"net/smtp"
	"strings"
	"text/template"
	"bytes"

	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/op/go-logging"
)

var (
	_ = pushers.Register("smtp", New)
)

var (
	log = logging.MustGetLogger("channels/smtp")
)

// Config defines a struct which holds configuration values for a Backend.
type SmtpConfig struct {
	Server  string `toml:"server"`
	Username string `toml:"username"`
	Password string `toml:"password"`
	Subject string `toml:"subject"`
	From string `toml:"from"`
	To []string `toml:"to"`
	BodyTemplate string `toml:"body_template"`
	tmpl *template.Template `toml:"-"`
}

// New returns a new instance of a FileBackend.
func New(options ...func(pushers.Channel) error) (pushers.Channel, error) {
	c := SmtpBackend{
		SmtpConfig: SmtpConfig{
		},
		request: make(chan map[string]interface{}),
	}

	for _, optionFn := range options {
		optionFn(&c)
	}

	if c.Server == "" {
		return nil, errors.New("Smtp channel: mail server not set, ex: mail.google.com")
	}

	if c.Username == "" {
		return nil, errors.New("Smtp channel: username not set, ex: abc@example.com")
	}
	if c.Password == "" {
		return nil, errors.New("Smtp channel: password not set, ex: password")
	}

	if c.Subject == "" {
		return nil, errors.New("Smtp channel: email subject not set, ex: Honeytrap alerts")
	}
	if c.From == "" {
		return nil, errors.New("Smtp channel: From address not set, ex: alert@example.com")
	}

	if c.To == nil || len(c.To) == 0 || c.To[0] == "" {
		return nil, errors.New("Smtp channel: At least first recipient must be set, ex: [\"admin1@example.com\",\"admin2@example.com\"]")
	}
	if c.BodyTemplate != "" {
		c.tmpl = template.Must(template.New("").Parse(c.BodyTemplate))
	} else {
		c.tmpl = nil
	}
	go c.writeLoop()

	return &c, nil
}

type SmtpBackend struct {
	SmtpConfig

	request chan map[string]interface{}
}

func (f *SmtpBackend) Close() {
	close(f.request)
}

// Send delivers the giving if it passes all filtering criteria into the
// FileBackend write queue.
func (f *SmtpBackend) Send(message event.Event) {
	mp := make(map[string]interface{})

	message.Range(func(key, value interface{}) bool {
		if keyName, ok := key.(string); ok {
			mp[keyName] = value
		}
		return true
	})

	f.request <- mp
}

// syncLoop handles configuration of the giving loop for writing to file.
func (f *SmtpBackend) writeLoop() {
	for {
		select {
		case req, ok := <-f.request:
			if !ok {
				return
			}
			msg := f.formatBody(&req)
			if msg != "" {
				f.sendMail(msg)
			} else {
				log.Infof("Empty email\n")
			}
		case <-time.After(time.Second):
		}
	}
}

func (f *SmtpBackend) sendMail(evt string) {
		// Setup host
		host := f.SmtpConfig.Server
		addr := "587"
	
		// Setup headers
		to := f.SmtpConfig.To
		toStr := strings.Join(f.SmtpConfig.To, ",")

		from := f.SmtpConfig.From

		msgStr := fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: %s\r\n\r\n%s\r\n", toStr, from, f.SmtpConfig.Subject, evt)
		msg := []byte(msgStr)
	
		// Set up authentication information.
		username := f.SmtpConfig.Username
		password := f.SmtpConfig.Password
	
		auth := smtp.PlainAuth("", username, password, host)
		log.Infof("Calling SendMail with: host=%s, from=%s, to=%s, msg=%s\n", host, from, to, msg)
		err := smtp.SendMail( host+":"+addr, auth, from, to, msg)
		if err != nil {
			log.Errorf("Fail to send email:%+q",err)
		}
}

func (f *SmtpBackend) formatBody(evt *map[string]interface{}) string {
	if f.SmtpConfig.BodyTemplate == "" {
		b, err := json.Marshal(evt)
		if err != nil {
			log.Errorf("Failed to marshal PushMessage to JSON : %+q", err)
			return ""
		}
		return string(b)
	}
	var buf bytes.Buffer
	err := f.SmtpConfig.tmpl.Execute(&buf, evt)
	if err != nil {
		log.Errorf("Fail to create email body:%+q",err)
		return ""
	}
	return buf.String()
}
