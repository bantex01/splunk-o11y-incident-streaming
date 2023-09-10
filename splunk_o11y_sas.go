package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fmt"

	"sync"

	"encoding/json"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
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

//var	configStruct Config
//var logger *log.Logger

func init() {

	logFile, err := os.OpenFile("mylog.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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
	ReadYamlConfig("./config.yaml")

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

		err := makeHTTPRequest("GET", url, headers, nil, &incidentStruct)
		if err != nil {
			logger.Println("Error from HTTP request:", err)
			return
		}

		/*
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				logger.Println("Error creating HTTP request:", err)
				continue
			}

			req.Header.Set("Content-Type", "application/json")
			//fmt.Printf("token is %s\n", token)
			req.Header.Set("X-SF-TOKEN", token)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				logger.Println("Error sending HTTP request:", err)
				return
			}
			//defer resp.Body.Close()

			//fmt.Println("Response Status:", resp.Status)
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				logger.Println("Error reading response body:", err)
			}
			//sb := string(body)
			//fmt.Println(sb)

			err = json.Unmarshal(body, &incidentStruct)
			if err != nil {
				logger.Println("Error unmarshalling response body:", err)
			}

		*/

		logger.Printf("Received %d events from SFX Source: %s\n", len(incidentStruct), label)

		// lets send the array of incidents off to be sent to splunk

		if len(incidentStruct) == 0 {
			logger.Printf("No events found for label %s ,waiting for next loop...", label)
			continue
		}

		// for each target, send the payload

		var targetWg sync.WaitGroup
		for _, targetLabel := range targets {
			logger.Printf("Label: %s has target of %v\n", label, targetLabel)
			for _, target := range configStruct.Targets {
				//typeStruct = nil
				if target.Label == targetLabel {
					//fmt.Printf("Found the target in config struct for %s, will need to create a struct of type %s\n", target, target.Type)
					switch target.Type {
					case "splunk":
						logger.Printf("We've found a splunk type target for source %s\n", label)
						typeStruct = &SplunkTarget{
							Label:      label,
							HECUrl:     target.HECUrl,
							HECToken:   target.HECToken,
							Source:     target.Source,
							SourceType: target.SourceType,
							Index:      target.Index,
							Payload:    incidentStruct,
						}
					case "file":
						logger.Printf("We've found a file type target for source %s\n", label)
						typeStruct = &FileTarget{
							Label:     label,
							FileName:  target.FileName,
							Incidents: incidentStruct,
						}
					}
				}

			}

			//fmt.Printf("At end of loop for targets, got this struct %+v\n", typeStruct)

			targetWg.Add(1)
			go typeStruct.formatAndSend(&targetWg)

		}

		//formatAndSend(label, splunkTargets, token, &incidentStruct)

		targetWg.Wait()

	}
	defer mainWg.Done()
}

func makeHTTPRequest(method, url string, requestHeaders map[string]string, requestBody interface{}, responseStruct interface{}) error {
	// Marshal the request body if provided
	var requestBodyBytes []byte
	if requestBody != nil {
		var err error
		requestBodyBytes, err = json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %v", err)
		}
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
	client := &http.Client{}
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

//func (target *SplunkTarget) formatAndSend(source string, splunkTargets []string, token string, incidents *[]IncidentPayload) {
func (target *SplunkTarget) formatAndSend(wg *sync.WaitGroup) {

	defer wg.Done()

	currentTime := time.Now()
	epochTime := currentTime.Unix()

	//logger.Printf("Sending to Splunk Target\n")

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

	// Convert the event to JSON

	//eventJSON, err := json.Marshal(batch)
	//if err != nil {
	//	logger.Println("Error marshaling JSON:", err)
	//	return
	//}

	// Send the event to Splunk HEC

	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Splunk " + target.HECToken,
	}

	var responseStruct struct {
		Text string `json:"text"`
		Code int    `json:"code"`
	}

	err := makeHTTPRequest("POST", target.HECUrl, headers, batch, &responseStruct)
	if err != nil {
		logger.Println("Error from HTTP request:", err)
		return
	} else {
		logger.Printf("HTTP Event Collector Send - Label: %s - Target: %s - Status Code: %d - Message: %s", target.Label, target.HECUrl, responseStruct.Code, responseStruct.Text)
	}

	/*
		client := &http.Client{}
		req, err := http.NewRequest("POST", target.HECUrl, bytes.NewBuffer(eventJSON))
		if err != nil {
			logger.Println("Error creating request:", err)
			return
		}

		req.Header.Set("Authorization", "Splunk "+target.HECToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			logger.Println("Error sending request:", err)
			return
		} else {
			logger.Println("Successful send to splunk")
		}

		defer resp.Body.Close()

		// Check the response status and handle accordingly
		if resp.StatusCode == http.StatusOK {
			logger.Println("Event(s) sent to HTTP event collector successfully")
		} else {
			fmt.Println("Event(s) send failed to HTTP Event Collector. Status code:", resp.StatusCode)
			// You can read the response body here for more details if needed
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				logger.Println("Error reading body:", err)
			}
			sb := string(body)
			logger.Println(sb)
		}*/

}

func (target *FileTarget) formatAndSend(wg *sync.WaitGroup) {

	defer wg.Done()
	logger.Printf("Sending to file target\n")

	logfilePath := "myfilelog.log"

	// Open the logfile for append (create it if it doesn't exist)
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
		} else {
			logger.Printf("Successful append to log file: %s", logfilePath)
		}

	}

}

func ReadYamlConfig(f string) {

	file := f
	//fmt.Printf("Reading config file %s\n", filePath)
	fileBase := filepath.Base(file)
	//fmt.Printf("file base is %s\n", fileBase)

	yamlFile, err := ioutil.ReadFile(fileBase)
	if err != nil {
		logger.Printf("yamlFile.Get err   #%v ", err)
		os.Exit(1)
	}

	// Lets make sure we unmarshal to the right struct depending on the arg sent to the function

	if strings.Contains(fileBase, "config.yaml") {
		//fmt.Println("event conf file found")
		err = yaml.Unmarshal(yamlFile, &configStruct)
		if err != nil {
			logger.Fatalf("Unmarshal: %v", err)
		}
		//fmt.Println(configStruct)
	}

}
