package main

// comment

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

type IncidentPayload struct {
	Active                    bool                    `json:"active,omitempty"`
	AnomalyState              string                  `json:"anomalyState,omitempty"`
	DetectLabel               string                  `json:"detectLabel,omitempty"`
	DetectorId                string                  `json:"detectorId,omitempty"`
	DetectorName              string                  `json:"detectorName,omitempty"`
	Events                    []*Event                `json:"events,omitempty"`
	IncidentId                string                  `json:"incidentId,omitempty"`
	Inputs                    *map[string]interface{} `json:"inputs,omitempty"`
	Severity                  string                  `json:"severity,omitempty"`
	IsMuted                   bool                    `json:"isMuted,omitempty"`
	TriggeredNotificationSent bool                    `json:"triggeredNotificationSent,omitempty"`
	TriggeredWhileMuted       bool                    `json:"triggeredWhileMuted,omitempty"`
}

type Event struct {
	AnomalyState     string                  `json:"anomalyState,omitempty"`
	DetectLabel      string                  `json:"detectLabel,omitempty"`
	DetectorId       string                  `json:"detectorId,omitempty"`
	DetectorName     string                  `json:"detectorName,omitempty"`
	EventAnnotations *map[string]interface{} `json:"event_annotations,omitempty"`
	Id               string                  `json:"id,omitempty"`
	IncidentId       string                  `json:"incidentId,omitempty"`
	Inputs           *map[string]interface{} `json:"inputs,omitempty"`
	Severity         string                  `json:"severity,omitempty"`
	Timestamp        int64                   `json:"timestamp,omitempty"`
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

	SFXIncidentRequestDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "so11y_sas_sfx_incident_http_request_duration_seconds",
			Help: "Duration of HTTP request to SFX to pull incidents in seconds",
		},
		[]string{"source"},
	)

	SFXIncidentCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "so11y_sas_sfx_incident_count",
			Help: "Count of incidents returned from SFX source",
		},
		[]string{"source"},
	)

	httpRequestErrorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "so11y_sas_http_request_error_total",
			Help: "Total number of http request errors",
		},
		[]string{"source"}, // You can add additional labels as needed
	)
)

func init() {

	logFile, err := os.OpenFile(log_file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logger.Println("Error opening log file:", err)
		logger.Println("GitHub Action build...")
		return
	}
	//defer logFile.Close()
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger = log.New(multiWriter, "splunk-o11y-sas: ", log.LstdFlags)

	prometheus.MustRegister(SFXIncidentRequestDuration)
	prometheus.MustRegister(SFXIncidentCount)
	prometheus.MustRegister(httpRequestErrorCounter)

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
		logger.Printf("SFX source - Label: %s - SFXRealm: %s - Gather Cycle Time: %d - Target List %v\n", sfxSource.Label, sfxSource.Realm, sfxSource.Cycle, sfxSource.Targets)
		mainWg.Add(1)
		go initiateSourceCollection(sfxSource.Label, sfxSource.Realm, sfxSource.Token, sfxSource.Cycle, sfxSource.Targets, &mainWg)
	}

	mainWg.Wait()
	logger.Println("No further processing, gracefully shutting down")

}

//comment

func initiateSourceCollection(label string, realm string, token string, cycle int, targets []string, mainWg *sync.WaitGroup) {

	var typeStruct SendTarget
	url := "https://api." + realm + ".signalfx.com/v2/incident?limit=10000"
	http_label := label + "_http_request"

	for range time.Tick(time.Second * time.Duration(cycle)) {

		var incidentStruct []IncidentPayload
		logger.Printf("Starting gather cycle (%d) for sfx source %s\n", cycle, label)

		headers := map[string]string{
			"Content-Type": "application/json",
			"X-SF-TOKEN":   token,
		}

		start := time.Now()
		err := makeHTTPRequest(http_label, "GET", url, headers, nil, &incidentStruct, false)
		if err != nil {
			httpRequestErrorCounter.WithLabelValues(http_label).Inc()
			logger.Printf("Error from HTTP request to gather incident data for source %s: %s", label, err)
			continue
		}

		SFXIncidentRequestDuration.WithLabelValues(label).Set(time.Since(start).Seconds())

		logger.Printf("Received %d events from SFX Source: %s\n", len(incidentStruct), label)

		SFXIncidentCount.WithLabelValues(label).Set(float64(len(incidentStruct)))

		// lets send the array of incidents off to be sent to splunk

		if len(incidentStruct) == 0 {
			logger.Printf("No events found for label %s ,waiting for next loop...", label)
			continue
		}

		// for each target, send the payload

		var targetWg sync.WaitGroup
		for _, targetLabel := range targets {
			//targetFound := false
			logger.Printf("Label: %s has target of %v\n", label, targetLabel)
			for _, target := range configStruct.Targets {
				//typeStruct = nil
				if target.Label == targetLabel {
					//targetFound = true
					//fmt.Printf("Found the target in config struct for %s, will need to create a struct of type %s\n", target, target.Type)
					switch target.Type {
					case "splunk":
						//logger.Printf("Found a splunk type target for source %s\n", label)
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
						//logger.Printf("Found a file type target for source %s\n", label)
						typeStruct = &FileTarget{
							Label:     label,
							FileName:  target.FileName,
							Incidents: incidentStruct,
						}
					}
				}

			}

			targetWg.Add(1)
			go typeStruct.formatAndSend(&targetWg)

		}

		targetWg.Wait()

	}
	defer mainWg.Done()
}

func makeHTTPRequest(label string, method, url string, requestHeaders map[string]string, requestBody interface{}, responseStruct interface{}, insecureSkipFlag bool) error {

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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipFlag}, // This potentially disables certificate verification
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
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if err != nil {
			return fmt.Errorf("unexpected response status: %v but failed to read response body: %v", resp.Status, err)
		} else {
			return fmt.Errorf("unexpected response status: %v - response: %s", resp.Status, string(respBody))
		}
	}

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

	http_label := "splunk_send_http_request"
	err := makeHTTPRequest(http_label, "POST", target.HECUrl, headers, batch, &responseStruct, target.SSLVerify)
	if err != nil {
		logger.Printf("Error from Splunk send HTTP request for source %s:%s", target.HECUrl, err)
		httpRequestErrorCounter.WithLabelValues(http_label).Inc()
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
	logger.Printf("Reading config file %s\n", file)

	yamlFile, err := ioutil.ReadFile(f)
	if err != nil {
		logger.Printf("yamlFile.Get err   #%v ", err)
		os.Exit(1)
	}

	err = yaml.Unmarshal(yamlFile, &configStruct)
	if err != nil {
		logger.Fatalf("Unmarshal: %v", err)
	}

	for ind, item := range configStruct.SFXSources {
		if item.Realm == "" {
			logger.Fatalf("SFX Source %s requires a realm setting", item.Label)
		}
		if item.Token == "" {
			logger.Fatalf("SFX Source %s requires a SFX token", item.Label)
		}
		if item.Cycle == 0 {
			configStruct.SFXSources[ind].Cycle = 60
			logger.Printf("SFX Source %s has no cycle time set, default set to 60 seconds", item.Label)
		}
		if len(item.Targets) < 1 {
			logger.Fatalf("SFX Source %s has no targets defined, you must set at least one target", item.Label)
		} else {
			for _, sourceTarget := range item.Targets {
				targetFound := false
				for _, taritem := range configStruct.Targets {
					if sourceTarget == taritem.Label {
						logger.Printf("SFX Source %s has a source target %s - match found in targets", item.Label, sourceTarget)
						targetFound = true
					}
				}
				if !targetFound {
					logger.Fatalf("SFX Source %s has a target of %s that is not defined", item.Label, sourceTarget)
				}

			}
		}

	}

	for _, target := range configStruct.Targets {
		switch target.Type {
		case "splunk":
			logger.Printf("Splunk target %s found, checking required configiuration", target.Label)
			if target.HECUrl == "" {
				logger.Fatalf("Splunk target %s requires a HEC Url to be supplied", target.Label)
			}
			if target.HECToken == "" {
				logger.Fatalf("Splunk target %s requires a HEC Token to be supplied", target.Label)
			}
			if target.Source == "" {
				logger.Printf("Splunk target %s has no source specified, source will be dictated by splunk settings server-side", target.Label)
			}
			if target.Index == "" {
				logger.Printf("Splunk target %s has no index specified, index will be determined by splunk settings server-side", target.Label)
			} else {
				logger.Printf("Splunk target %s has an index specified, ensure the index exists and the HEC input allows data to be sent to it", target.Label)
			}
			if target.SourceType == "" {
				logger.Printf("Splunk target %s has no sourcetype specified, sourcetype will be determined by splunk settings server-side", target.Label)
			} else {
				logger.Printf("Splunk target %s has a sourcetype specified, ensure the sourcetype exists for successful parsing", target.Label)
			}
			if !target.SSLVerify {
				logger.Printf("Splunk target %s has no ssl_insecure_skip_verify specified, default set to \"false\"", target.Label)
			}
		case "file":
			logger.Printf("File target %s found, checking required configuration", target.Label)
			if target.FileName == "" {
				logger.Fatalf("File target %s requires file name to be specified", target.Label)
			}
		default:
			logger.Printf("An unknown target type of %s has been found, only \"splunk\" and \"file\" types are allowed", target.Type)

		}

	}

}
