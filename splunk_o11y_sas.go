package main

import (
	"bytes"
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

	"gopkg.in/yaml.v2"
)

type Config struct {
	SFXSources []SFXSource `yaml:"sfx_sources"`
	Targets    []Target    `yaml:"targets"`
}

type SFXSource struct {
	Label         string   `yaml:"label"`
	Realm         string   `yaml:"realm"`
	Token         string   `yaml:"token"`
	Cycle         int      `yaml:"cycle"`
	SplunkTargets []string `yaml:"splunk_targets"`
}

type Target struct {
	Label    string `yaml:"label"`
	Type     string `yaml:"type"`
	HECUrl   string `yaml:"hec_url"`
	HECToken string `yaml:"hec_token"`
	FileName string `yaml:"file_name"`
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

var configStruct Config

func main() {

	fmt.Println("Running...")
	ReadYamlConfig("./config.yaml")

	// let's set off go routines for each SFX source

	var wg sync.WaitGroup

	for _, sfxSource := range configStruct.SFXSources {
		fmt.Printf("Gathering incident data for %s\n", sfxSource.Label)
		wg.Add(1)
		go initiateSourceCollection(sfxSource.Label, sfxSource.Realm, sfxSource.Token, sfxSource.Cycle, sfxSource.SplunkTargets, &wg)
	}

	wg.Wait()
	fmt.Println("No further processing, gracefully shutting down")

}

func initiateSourceCollection(label string, realm string, token string, cycle int, splunkTargets []string, wg *sync.WaitGroup) {

	var incidentStruct []IncidentPayload
	url := "https://api." + realm + ".signalfx.com/v2/incident"
	fmt.Printf("url is %s\n", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	fmt.Printf("token is %s\n", token)
	req.Header.Set("X-SF-TOKEN", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Response Status:", resp.Status)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
	}
	sb := string(body)
	fmt.Println(sb)

	err = json.Unmarshal(body, &incidentStruct)
	if err != nil {
		fmt.Println("Error unmarshalling:", err)
	}
	fmt.Printf("Received %d events\n", len(incidentStruct))

	// lets send the array of incidents off to be sent to splunk

	// for each target, send the payload
	formatSendSplunk(label, splunkTargets, token, &incidentStruct)

	defer wg.Done()
}

func formatSendSplunk(source string, splunkTargets []string, token string, incidents *[]IncidentPayload) {

	for _, target := range splunkTargets {
		fmt.Printf("Target passed is %s\n", target)
		for _, splunkTarget := range configStruct.SplunkTargets {
			if target == splunkTarget.Label {
				fmt.Printf("We've found a match on splunk target. SFX splunk target is %s - splunk target details are...\n", target)
				fmt.Printf("Label: %s - URL: %s - HEC Token: %s\n", splunkTarget.Label, splunkTarget.HECUrl, splunkTarget.HECToken)
			}
		}

	}

	type Event struct {
		Time       string `json:"time"`
		Host       string `json:"host"`
		Source     string `json:"source"`
		Sourcetype string `json:"sourcetype"`
		Event      string `json:"event"`
	}

	fmt.Printf("Received source %s\n", source)
	fmt.Println(incidents)
	for _, incident := range *incidents {
		fmt.Printf("Detector Name: %s - Severity: %s\n", incident.DetectorName, incident.Severity)
	}

	//

	now := time.Now()

	for _, incident := range *incidents {

		// Construct the Event data
		hecEvent := Event{
			Event:      "severity=" + incident.Severity + " detector_name=" + incident.DetectorName,
			Host:       source,
			Sourcetype: "manual",
			Time:       now.Format("Mon Jan 2 15:04:05 MST 2006"),
			Source:     "splunk_sas",
		}

		// Convert the event to JSON
		eventJSON, err := json.Marshal(hecEvent)
		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			return
		}

		fmt.Println(eventJSON)

		// Send the event to Splunk HEC
		client := &http.Client{}
		req, err := http.NewRequest("POST", "http://localhost:8088/services/collector", bytes.NewBuffer(eventJSON))
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		req.Header.Set("Authorization", "Splunk aa18b9dd-ea02-4c63-941b-b5f8e1061d59")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}

		defer resp.Body.Close()

		// Check the response status and handle accordingly
		if resp.StatusCode == http.StatusOK {
			fmt.Println("Event sent successfully")
		} else {
			fmt.Println("Event send failed. Status code:", resp.StatusCode)
			// You can read the response body here for more details if needed
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
		log.Printf("yamlFile.Get err   #%v ", err)
		os.Exit(1)
	}

	// Lets make sure we unmarshal to the right struct depending on the arg sent to the function

	if strings.Contains(fileBase, "config.yaml") {
		//fmt.Println("event conf file found")
		err = yaml.Unmarshal(yamlFile, &configStruct)
		if err != nil {
			log.Fatalf("Unmarshal: %v", err)
		}
		fmt.Println(configStruct)
	}

}
