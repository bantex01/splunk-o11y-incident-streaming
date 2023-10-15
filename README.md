# Splunk Observability Incident Streaming Service

This repository contains the splunk-o11y-incident-streaming go code. The program will continually (configurable) send a stream of open splunk o11y incident data to as many Splunk Enterprise targets as required. 

## Details

This is an alternative to the official Splunk o11y supplied web-hook to send incident data to your Splunk Enterprise instance(s). The service aims to address the following potential issues with the official integration when using ITSI (IT Service Intelligence) to manage your operational alerting but can also be used to ensure an up-to date view of your open incidents in your Splunk Observability org(s):

- Missed alert update should the webhook functionality fail, meaning inaccurate operational dashboards, or potentially, ITSI episodes staying open indefinitely or not be created at all
- Accidental closure of ongoing issues. Should an incident be closed manually without a clearing event from Splunk Observability, there would be no further update, no open incident and a production issue would still be firing
- Premature closure of ITSI episodes. Episode rules have to be configured to wait a configurable length of time before making a decision on breaking/closing the episode due to inactivity. This service allows you to have small look-back windows to gather incident data as well as allowing ITSI to close episodes timely

 ### Configuration

A configuration file called splunk_o11y_sas.yaml is required.

The table below details the configurable options:

#### sfx_sources

<table>
  <tr>
    <th>Config Name</th>
    <th>Description</th>
    <th>Required</th>
    <th>Default</th>
    <th>Sample</th>
  </tr>
  <tr>
    <td>label</td>
    <td>A label for the Splunk o11y Source - this label will be used as the source of the events</td>
    <td>Yes</td>
    <td>NA</td>
    <td>US1-Prod</td>
  </tr>
  <tr>
    <td>realm</td>
    <td>The Splunk o11y realm you want to gather incident data from</td>
    <td>Yes</td>
    <td>NA</td>
    <td>us1</td>
  </tr>
  <tr>
    <td>token</td>
    <td>The Splunk o11y token for the realm you want to gather incident data from</td>
    <td>Yes</td>
    <td>NA</td>
    <td>some_token</td>
  </tr>
  <tr>
    <td>cycle</td>
    <td>How often, in seconds, you wish to gather open o11y incident data</td>
    <td>No</td>
    <td>60</td>
    <td>60</td>
  </tr>
  <tr>
    <td>targets</td>
    <td>An array of targets to send the incident data to - the target name must match a target configured in the targets section of the configuration file</td>
    <td>Yes</td>
    <td>NA</td>
    <td>splunk_prod, splunk_dev</td>
  </tr>
</table>

#### targets

<table>
  <tr>
    <th>Config Name</th>
    <th>Description</th>
    <th>Required</th>
    <th>Default</th>
    <th>Sample</th>
  </tr>
  <tr>
    <td>label</td>
    <td>A label for the target</td>
    <td>Yes</td>
    <td>NA</td>
    <td>splunk_prod</td>
  </tr>
  <tr>
    <td>type</td>
    <td>The type of target (splunk or file)</td>
    <td>Yes</td>
    <td>NA</td>
    <td>splunk</td>
  </tr>
</table>

##### Splunk Target Options

<table>
  <tr>
    <th>Config Name</th>
    <th>Description</th>
    <th>Required</th>
    <th>Default</th>
    <th>Sample</th>
  </tr>
  <tr>
    <td>hec_url</td>
    <td>The URL for the HEC input</td>
    <td>Yes</td>
    <td>NA</td>
    <td>https://1.1.1.1:8088/services/collector</td>
  </tr>
  <tr>
    <td>hec_token</td>
    <td>The Splunk HEC token</td>
    <td>Yes</td>
    <td>NA</td>
    <td>us1</td>
  </tr>
  <tr>
    <td>source</td>
    <td>The Splunk source to use in the event</td>
    <td>No</td>
    <td>NA</td>
    <td>splunk_o11y_sas</td>
  </tr>
  <tr>
    <td>sourcetype</td>
    <td>The Splunk sourcetype to use in the event</td>
    <td>No</td>
    <td>NA</td>
    <td>my_splunk_o11y_sas_sourcetype</td>
  </tr>
  <tr>
    <td>index</td>
    <td>The Splunk index to send the events to</td>
    <td>No</td>
    <td>NA</td>
    <td>my_splunk_o11y_sas_index</td>
  </tr>
  <tr>
    <td>ssl_insecure_skip_verify</td>
    <td>Turn off SSL cert verification if sending over https</td>
    <td>No</td>
    <td>false</td>
    <td>true</td>
  </tr>
</table>

##### File Target Options

<table>
  <tr>
    <th>Config Name</th>
    <th>Description</th>
    <th>Required</th>
    <th>Default</th>
    <th>Sample</th>
  </tr>
  <tr>
    <td>file_name</td>
    <td>The full path to the file you wish to update with incident data</td>
    <td>Yes</td>
    <td>NA</td>
    <td>/splunk_o11y_sas/incident.out</td>
  </tr>
</table>

Here is a sample of the configuration:

```
---
sfx_sources:
- label: splunk_o11y_dev
  realm: us1
  token: some_token
  cycle: 60
  targets:
  - dev_splunk
- label: splunk_o11y_prod
  realm: eu0
  token: some_token
  cycle: 30
  targets:
  - prod_splunk
  - prod_textfile
targets:
- label: prod_splunk
  type: splunk
  hec_url: https://1.1.1.1:8088/services/collector
  hec_token: some_token
  source: splunk_sas
  sourcetype: splunk_sas_st
  index: splunk_o11y_events
  ssl_insecure_skip_verify: true
- label: dev_splunk
  type: splunk
  hec_url: https://1.1.1.2:8088/services/collector
  hec_token: some_token
  ssl_insecure_skip_verify: true
- label: prod_textfile
  type: file
  file_name: splunk_o11y_sas_prod.out
```
