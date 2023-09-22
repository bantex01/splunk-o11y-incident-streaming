package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fmt"

	"sync"

	"encoding/json"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
)

const (
	config_file = "config/splunk_o11y_sas.yaml"
	log_file    = "splunk_o11y_sas.log"
)

type Config struct {
	SFXSources []SFXSource `yaml:"sfx_sources"`
	Targets    []Target    `yaml:"targets"`
}

type SFXSource struct {
	Label   string   `yaml:"label"`
	Realm   string   `yaml:"realm"`
	Token   string   `yaml:"token"`
	Cycle   int      `yaml:"cycle"`
	Targets []string `yaml:"targets"`
}

type Target struct {
	Label      string `yaml:"label"`
	Type       string `yaml:"type"`
	HECUrl     string `yaml:"hec_url"`
	HECToken   string `yaml:"hec_token"`
	FileName   string `yaml:"file_name"`
	Source     string `yaml:"source"`
	SourceType string `yaml:"sourcetype"`
	Index      string `yaml:"index"`
	SSLVerify  bool   `yaml:"ssl_insecure_skip_verify"`
}

type EventAnnotations struct {
	FireThreshold    string `json:"fire_threshold"`
	ResourceType     string `json:"resource_type"`
	SFUIIncidentInfo string `json:"sfui_incidentInformation"`
}

type Inputs struct {
	Key   Key   `json:"_S1"`
	Value Value `json:"_S2"`
}

type Key struct {
	Location   string `json:"location"`
	LocationID string `json:"location_id"`
	SFMetric   string `json:"sf_metric"`
	Test       string `json:"test"`
	TestID     string `json:"test_id"`
	TestType   string `json:"test_type"`
}

type Value struct {
	Value string `json:"value"`
}

type Event struct {
	AnomalyState     string           `json:"anomalyState"`
	DetectLabel      string           `json:"detectLabel"`
	DetectorID       string           `json:"detectorId"`
	DetectorName     string           `json:"detectorName"`
	EventAnnotations EventAnnotations `json:"event_annotations"`
	ID               string           `json:"id"`
	IncidentID       string           `json:"incidentId"`
	Inputs           Inputs           `json:"inputs"`
	LinkedTeams      interface{}      `json:"linkedTeams"`
	Severity         string           `json:"severity"`
	Timestamp        int64            `json:"timestamp"`
}

type IncidentPayload struct {
	Active                    bool    `json:"active"`
	AnomalyState              string  `json:"anomalyState"`
	DetectLabel               string  `json:"detectLabel"`
	DetectorID                string  `json:"detectorId"`
	DetectorName              string  `json:"detectorName"`
	DisplayBody               string  `json:"displayBody"`
	Events                    []Event `json:"events"`
	IncidentID                string  `json:"incidentId"`
	IsMuted                   bool    `json:"isMuted"`
	Severity                  string  `json:"severity"`
	TriggeredNotificationSent bool    `json:"triggeredNotificationSent"`
	TriggeredWhileMuted       bool    `json:"triggeredWhileMuted"`
}

type SplunkTarget struct {
	Label      string
	HECUrl     string
	HECToken   string
	Source     string
	SourceType string
	Index      string
	Payload    []IncidentPayload
	SSLVerify  bool
}

type FileTarget struct {
	Label     string
	FileName  string
	Incidents []IncidentPayload
}

type SendTarget interface {
	formatAndSend(*sync.WaitGroup)
}

var (
	configStruct Config
	logger       *log.Logger
)

func init() {

	logFile, err := os.OpenFile(log_file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	//defer logFile.Close()
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger = log.New(multiWriter, "splunk-o11y-sas: ", log.LstdFlags)

}

func main() {

	//logger := log.New(multiWriter, "splunk-o11y-sas: ", log.LstdFlags)

	logger.Println("Starting splunk_o11y_sas service...")
	ReadYamlConfig(config_file)

	go func() {
		for {
			logger.Println("Starting metrics endpoint on port 2112")
			http.Handle("/metrics", promhttp.Handler())
			http.ListenAndServe(":2112", nil)
		}
	}()

	// let's set off go routines for each SFX source

	var mainWg sync.WaitGroup

	for _, sfxSource := range configStruct.SFXSources {
		logger.Printf("Found SFX source with detail - Label: %s - SFXRealm: %s - Gather Cycle Time: %d - Target List %v\n", sfxSource.Label, sfxSource.Realm, sfxSource.Cycle, sfxSource.Targets)
		mainWg.Add(1)
		go initiateSourceCollection(sfxSource.Label, sfxSource.Realm, sfxSource.Token, sfxSource.Cycle, sfxSource.Targets, &mainWg)
	}

	mainWg.Wait()
	logger.Println("No further processing, gracefully shutting down")

}

//comment

func initiateSourceCollection(label string, realm string, token string, cycle int, targets []string, mainWg *sync.WaitGroup) {

	var typeStruct SendTarget
	var incidentStruct []IncidentPayload
	url := "https://api." + realm + ".signalfx.com/v2/incident"
	//fmt.Printf("url is %s\n", url)

	for range time.Tick(time.Second * time.Duration(cycle)) {

		logger.Printf("Starting gather cycle (%d) for sfx source %s\n", cycle, label)

		headers := map[string]string{
			"Content-Type": "application/json",
			"X-SF-TOKEN":   token,
		}

		err := makeHTTPRequest("GET", url, headers, nil, &incidentStruct, true)
		if err != nil {
			logger.Println("Error from HTTP request:", err)
			return
		}

		logger.Printf("Received %d events from SFX Source: %s\n", len(incidentStruct), label)

		// lets send the array of incidents off to be sent to splunk

		if len(incidentStruct) == 0 {
			logger.Printf("No events found for label %s ,waiting for next loop...", label)
			continue
		}

		// for each target, send the payload

		var targetWg sync.WaitGroup
		for _, targetLabel := range targets {
			targetFound := false
			logger.Printf("Label: %s has target of %v\n", label, targetLabel)
			for _, target := range configStruct.Targets {
				//typeStruct = nil
				if target.Label == targetLabel {
					targetFound = true
					//fmt.Printf("Found the target in config struct for %s, will need to create a struct of type %s\n", target, target.Type)
					switch target.Type {
					case "splunk":
						logger.Printf("Found a splunk type target for source %s\n", label)
						typeStruct = &SplunkTarget{
							Label:      label,
							HECUrl:     target.HECUrl,
							HECToken:   target.HECToken,
							Source:     target.Source,
							SourceType: target.SourceType,
							Index:      target.Index,
							Payload:    incidentStruct,
							SSLVerify:  target.SSLVerify,
						}
					case "file":
						logger.Printf("Found a file type target for source %s\n", label)
						typeStruct = &FileTarget{
							Label:     label,
							FileName:  target.FileName,
							Incidents: incidentStruct,
						}
					}
				}

			}

			if !targetFound {
				logger.Printf("No target with label %s has been found", targetLabel)
			} else {
				targetWg.Add(1)
				go typeStruct.formatAndSend(&targetWg)
			}

		}

		targetWg.Wait()

	}
	defer mainWg.Done()
}

func makeHTTPRequest(method, url string, requestHeaders map[string]string, requestBody interface{}, responseStruct interface{}, insecureSkipFlag bool) error {
	// Marshal the request body if provided
	var requestBodyBytes []byte
	var tr *http.Transport
	var client *http.Client

	if requestBody != nil {
		var err error
		requestBodyBytes, err = json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %v", err)
		}
	}

	if strings.Contains(url, "https") {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipFlag}, // This disables certificate verification
		}
		client = &http.Client{Transport: tr}
	} else {
		client = &http.Client{}
	}

	// Create a request
	req, err := http.NewRequest(method, url, bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set request headers
	for key, value := range requestHeaders {
		req.Header.Set(key, value)
	}

	// Perform the HTTP request
	//client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	// Check the response status
	if resp.StatusCode != http.StatusOK {
		//return fmt.Errorf("unexpected response status: %v", resp.Status)
		if err != nil {
			return fmt.Errorf("unexpected response status: %v but failed to read response body: %v", resp.Status, err)
		} else {
			return fmt.Errorf("unexpected response status: %v - response: %s", resp.Status, string(respBody))
		}
	}

	// Unmarshal the response into the provided struct

	err = json.Unmarshal(respBody, responseStruct)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return nil
}

func (target *SplunkTarget) formatAndSend(wg *sync.WaitGroup) {

	defer wg.Done()

	currentTime := time.Now()
	epochTime := currentTime.Unix()

	type Event struct {
		Time       int64           `json:"time"`
		Host       string          `json:"host"`
		Source     string          `json:"source,omitempty"`
		SourceType string          `json:"sourcetype,omitempty"`
		Event      IncidentPayload `json:"event"`
		Index      string          `json:"index,omitempty"`
	}

	var batch []Event

	for _, incident := range target.Payload {
		hecEvent := Event{
			Time:       epochTime,
			Event:      incident,
			Host:       target.Label,
			SourceType: target.SourceType,
			Source:     target.Source,
			Index:      target.Index,
		}

		batch = append(batch, hecEvent)
	}

	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Splunk " + target.HECToken,
	}

	var responseStruct struct {
		Text string `json:"text"`
		Code int    `json:"code"`
	}

	err := makeHTTPRequest("POST", target.HECUrl, headers, batch, &responseStruct, target.SSLVerify)
	if err != nil {
		logger.Println("Error from HTTP request:", err)
		return
	} else {
		logger.Printf("HTTP Event Collector Send - Label: %s - Target: %s - Status Code: %d - Message: %s", target.Label, target.HECUrl, responseStruct.Code, responseStruct.Text)
	}

}

func (target *FileTarget) formatAndSend(wg *sync.WaitGroup) {

	defer wg.Done()
	logger.Printf("Label: %s - Attempting to send incident data to %s\n", target.Label, target.FileName)

	logfilePath := target.FileName

	logFile, err := os.OpenFile(logfilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Println("Error opening logfile:", err)
		return
	}
	defer logFile.Close()

	currentTime := time.Now()
	formattedTime := currentTime.Format("2006-01-02 15:04:05")

	type Event struct {
		Time  string          `json:"time"`
		Host  string          `json:"host"`
		Event IncidentPayload `json:"event"`
	}

	for _, incident := range target.Incidents {
		fileEvent := Event{
			Time:  formattedTime,
			Event: incident,
			Host:  target.Label,
		}

		eventJSON, err := json.Marshal(fileEvent)
		if err != nil {
			logger.Println("Error marshaling JSON:", err)
			return
		}

		if _, err := logFile.WriteString(string(eventJSON) + "\n"); err != nil {
			logger.Println("Error writing to logfile:", err)
			return
		}
	}

	logger.Printf("Label: %s - Successful incident data append to %s\n", target.Label, target.FileName)

}

func ReadYamlConfig(f string) {

	file := f
	fmt.Printf("Reading config file %s\n", file)

	yamlFile, err := ioutil.ReadFile(f)
	if err != nil {
		logger.Printf("yamlFile.Get err   #%v ", err)
		os.Exit(1)
	}

	// Lets make sure we unmarshal to the right struct depending on the arg sent to the function

	err = yaml.Unmarshal(yamlFile, &configStruct)
	if err != nil {
		logger.Fatalf("Unmarshal: %v", err)
	}

}
