/*
Copyright 2020 Dynatrace LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
)

const enforceLeadingDigits = true

var fileNameFormat = regexp.MustCompile("(^\\d+[-].+)")

var endpoints = Endpoints{
	"SecurityProblemsAll": "/api/v2/securityProblems?pageSize=500",
	"SecurityProblems":    "/api/v2/securityProblems",
	"Processes":           "/api/v1/entity/infrastructure/processes",
	"Hosts":               "/api/v1/entity/infrastructure/hosts",
}

func main() {
	var err error
	var cookieJar *cookiejar.Jar
	if cookieJar, err = cookiejar.New(nil); err != nil {
		panic(err)
	}
	client := &http.Client{Jar: cookieJar}
	processor := &Processor{
		Config:               new(Config).Parse(),
		Client:               client,
		ProcessInstanceCache: &ProcessInstanceCache{},
	}
	if err = processor.Process(); err != nil {
		panic(err)
	}
}

// Processor has no documentation
type Processor struct {
	Config               *Config
	Client               *http.Client
	ProcessInstanceCache *ProcessInstanceCache
}

// Process has no documentation
func (p *Processor) Process() error {
	var err error
	pList, err := p.getSecurityProblemList("SecurityProblemsAll")

	if p.Config.Verbose {
		fmt.Printf("Total number of vulnerabilities=%d\n", len(pList))
	}
	if err != nil {
		panic(err)
	}

	//processesByLibrary := ProcessesByLibrary{}
	//librariesByProcess := LibrariesByProcess{}
	for elem, problemId := range pList {
		exposedEntitiesList, err := p.getSecurityProblemInfo(problemId)
		if err != nil {
			log.Fatal(err)
		}

		if p.Config.Verbose {
			fmt.Printf("%d. %s\n", elem, problemId)
		}
		for _, exposedEntity := range exposedEntitiesList {
			fmt.Printf("%s,%s,%s,%s\n", exposedEntity.SecurityProblemId, exposedEntity.CveId, exposedEntity.ProcessInstanceName, exposedEntity.HostInstanceName)
			/*fmt.Fprintf(%s","%s,)
			fmt.Println("ProblemId=" + exposedEntity.SecurityProblemId)
			fmt.Println("CveId=" + exposedEntity.CveId)
			fmt.Println("ProcessInstanceId=" + exposedEntity.ProcessInstanceId)
			fmt.Println("ProcessInstanceName=" + exposedEntity.ProcessInstanceName)
			fmt.Println("HostInstanceName=" + exposedEntity.HostInstanceName)
			//fmt.Println("Library=" + securityProblem.Library)
			*/
			/*for _, process := range securityProblem.ProcessInstanceNameList {
				fmt.Println(process)
			}*/
			/*if !p.Config.GroupByProcess {
				processNames, found := processesByLibrary[securityProblem.Library]
				if !found {
					processNames = &ProcessNames{ProcessInstanceNames: []string{}}
					processesByLibrary[securityProblem.Library] = processNames
				}

				for _, processName := range securityProblem.ProcessInstanceNameList {
					found = false
					for _, pName := range processNames.ProcessInstanceNames {
						if pName == processName {
							found = true
							break
						}
					}

					if !found {
						processNames.ProcessInstanceNames = append(processNames.ProcessInstanceNames, processName)
					}
				}
			} else {
				libraryName := securityProblem.Library
				for _, processName := range securityProblem.ProcessInstanceNameList {
					lNames, found := librariesByProcess[processName]
					if !found {
						librariesByProcess[processName] = &Libraries{LibraryNames: []string{libraryName}}
					} else {
						found = false
						for _, lName := range lNames.LibraryNames {
							if lName == libraryName {
								found = true
								break
							}
						}
						if !found {
							lNames.LibraryNames = append(lNames.LibraryNames, libraryName)
						}
					}
				}
			}*/
		}
	}

	/*if p.Config.Verbose {
		fmt.Println("===========================================")
		fmt.Println("Process Cache Entries")
		fmt.Println("===========================================")
		for processId, name := range *p.ProcessInstanceCache {
			fmt.Printf("%s: %s\n", processId, *name)
		}
		fmt.Println("===========================================")
	}

	if !p.Config.GroupByProcess {
		for key, pByLibrary := range processesByLibrary {
			fmt.Printf(key + ",")
			for idx, value := range pByLibrary.ProcessInstanceNames {
				fmt.Printf(value)
				if idx < len(pByLibrary.ProcessInstanceNames)-1 {
					fmt.Printf(",")
				}
			}
			fmt.Println()
		}
	} else {
		for key, lbyProcess := range librariesByProcess {
			fmt.Printf(key + ",")
			for idx, value := range lbyProcess.LibraryNames {
				fmt.Printf(value)
				if idx < len(lbyProcess.LibraryNames)-1 {
					fmt.Printf(",")
				}
			}
			fmt.Println()
		}
	}*/
	return nil
}

func (p *Processor) getSecurityProblemList(endpointName string) ([]string, error) {
	var err error
	var req *http.Request
	endpointURL := p.Config.URL + endpoints[endpointName]
	if req, err = p.setupHTTPRequest("GET", endpointURL); err != nil {
		return nil, err
	}
	var resp *http.Response
	if resp, err = p.Client.Do(req); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	pList, err := p.processSecurityProblemsResponse(resp)
	if err != nil {
		return nil, err
	}
	return pList, nil
}

func (p *Processor) getSecurityProblemInfo(problemId string) ([]*ExposedEntityInfo, error) {
	var err error
	var req *http.Request
	endpointURL := p.Config.URL + endpoints["SecurityProblems"] + "/" + problemId + "?fields=%2BexposedEntities"
	if req, err = p.setupHTTPRequest("GET", endpointURL); err != nil {
		return nil, err
	}
	var resp *http.Response
	if resp, err = p.Client.Do(req); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	infoList, err := p.processProblemInfoResponse(resp)
	if p.Config.Debug {
		fmt.Printf("InfoList size is %d\n", len(infoList))
	}
	if err != nil {
		return nil, err
	}
	err = p.getProcessInstanceData(infoList)
	//fmt.Printf("theList size is %d\n", len(theList))

	if err != nil {
		return nil, err
	}

	return infoList, nil
}

func (p *Processor) setupHTTPRequest(method string, endpointURL string) (*http.Request, error) {
	if p.Config.Debug {
		log.Println(fmt.Sprintf("  [HTTP] %s %s", method, endpointURL))
	}
	var err error
	var req *http.Request
	if req, err = http.NewRequest(method, endpointURL, nil); err != nil {
		return nil, err
	}
	if p.Config.Debug {
		log.Println(fmt.Sprintf("  [HTTP] %s: %s", "accept", "application/json"))
	}
	req.Header.Set("accept", "application/json; charset=utf-8")

	/*if p.Config.Debug {
		log.Println(fmt.Sprintf("  [HTTP] %s: %s", "Authorization", "Api-Token "+p.Config.APIToken))
	}*/
	req.Header.Add("Authorization", "Api-Token "+p.Config.APIToken)

	return req, nil
}

func (p *Processor) processSecurityProblemsResponse(resp *http.Response) ([]string, error) {
	//fmt.Println("processResponse")
	body, _ := ioutil.ReadAll(resp.Body)

	if p.Config.Debug {
		log.Println("  [HTTP] Status: " + resp.Status)
	}
	if resp.StatusCode >= 400 {
		var errorEnvelope ErrorEnvelope

		json.Unmarshal([]byte(body), &errorEnvelope)
		if errorEnvelope.RESTError == nil {
			var restError RESTError
			json.Unmarshal([]byte(body), &restError)
			return nil, &restError
		}
		return nil, &errorEnvelope
	}
	var successEnvelope SecurityProblemSuccessEnvelope
	json.Unmarshal([]byte(body), &successEnvelope)
	if p.Config.Debug {
		log.Println(successEnvelope.TotalCount)
	}

	var pList []string
	for _, problemList := range successEnvelope.SecurityProblems {
		if p.Config.Debug {
			log.Println(problemList.SecurityProblemId)
		}
		pList = append(pList, problemList.SecurityProblemId)
	}
	return pList, nil
}

func (p *Processor) processProblemInfoResponse(resp *http.Response) ([]*ExposedEntityInfo, error) {
	//fmt.Println("processResponse")
	body, _ := ioutil.ReadAll(resp.Body)

	if p.Config.Debug {
		log.Println("  [HTTP] Status: " + resp.Status)
	}
	if resp.StatusCode >= 400 {
		var errorEnvelope ErrorEnvelope

		json.Unmarshal([]byte(body), &errorEnvelope)
		if errorEnvelope.RESTError == nil {
			var restError RESTError
			json.Unmarshal([]byte(body), &restError)
			return nil, &restError
		}
		return nil, &errorEnvelope
	}
	var securityProblemInfoEnvelope SecurityProblemInfoEnvelope
	json.Unmarshal([]byte(body), &securityProblemInfoEnvelope)
	if p.Config.Debug {
		log.Println("ProblemId=" + securityProblemInfoEnvelope.SecurityProblemId)
		//		log.Println(&securityProblemInfoEnvelope)
	}

	var infoList []*ExposedEntityInfo
	// Concatinating all CVEs into one string
	cveId := strings.Join(securityProblemInfoEnvelope.CveIds, ";")

	for _, exposedEntity := range securityProblemInfoEnvelope.ExposedEntities {
		if p.Config.Debug {
			log.Println(exposedEntity)
			log.Println(cveId)
		}

		info := &ExposedEntityInfo{}
		//		if len(compList.VulnerableProcesses) > 0 {
		info.SecurityProblemId = securityProblemInfoEnvelope.SecurityProblemId
		info.ProcessInstanceId = exposedEntity
		info.CveId = cveId
		infoList = append(infoList, info)
		//		}
	}
	return infoList, nil
}

func (p *Processor) getProcessInstanceData(list []*ExposedEntityInfo) error {
	var err error
	var req *http.Request
	//var info *SecurityProblemInfo
	//var newList []SecurityProblemInfo
	for index, process := range list {
		processEnvelope, found := p.checkProcessCache(process.ProcessInstanceId)
		if !found {
			endpointURL := p.Config.URL + endpoints["Processes"] + "/" + process.ProcessInstanceId
			if req, err = p.setupHTTPRequest("GET", endpointURL); err != nil {
				return err
			}
			var resp *http.Response
			if resp, err = p.Client.Do(req); err != nil {
				return err
			}
			defer resp.Body.Close()

			processEnvelope, err = p.getProcessData(resp)
			if err != nil {
				return err
			}
			(*p.ProcessInstanceCache)[process.ProcessInstanceId] = processEnvelope
		}
		hostName, err := p.getProcessHostName(processEnvelope.FromRelationships.IsProcessOf[0])
		if err != nil {
			return err
		}
		//processNames = append(processNames, processName)
		list[index].ProcessInstanceName = processEnvelope.DisplayName
		list[index].HostInstanceName = hostName
	}
	return nil

	//info.ProcessInstanceNameList = processNames
	//list[index] = info
}

func (p *Processor) getProcessHostName(hostId string) (string, error) {
	var err error
	var req *http.Request
	endpointURL := p.Config.URL + endpoints["Hosts"] + "/" + hostId
	if req, err = p.setupHTTPRequest("GET", endpointURL); err != nil {
		return "", err
	}
	var resp *http.Response
	if resp, err = p.Client.Do(req); err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	type HostInfo struct {
		DisplayName string
	}
	var hostInfo HostInfo
	json.Unmarshal([]byte(body), &hostInfo)

	return hostInfo.DisplayName, nil
}

func (p *Processor) getProcessData(resp *http.Response) (*ProcessEnvelope, error) {
	body, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println("In Process Data")
	if p.Config.Debug {
		log.Println("  [HTTP] Status: " + resp.Status)
	}
	if resp.StatusCode >= 400 {
		var errorEnvelope ErrorEnvelope

		json.Unmarshal([]byte(body), &errorEnvelope)
		if errorEnvelope.RESTError == nil {
			var restError RESTError
			json.Unmarshal([]byte(body), &restError)
			return nil, &restError
		}
		return nil, &errorEnvelope
	}

	var processEnvelope ProcessEnvelope
	json.Unmarshal([]byte(body), &processEnvelope)
	if processEnvelope.DisplayName != "" && p.Config.Verbose {
		log.Println(fmt.Sprintf("  id: %s", processEnvelope.DisplayName))
	}
	//pName := processEnvelope.DisplayName
	//pNameRep := strings.ReplaceAll(pName, "/", "\\/")
	//relationship := processEnvelope.FromRelationships
	//hostId := relationship.IsProcessOf[0]
	return &processEnvelope, nil
}

func (p *Processor) checkProcessCache(processId string) (*ProcessEnvelope, bool) {
	processEnvelope, found := (*p.ProcessInstanceCache)[processId]
	if found {
		return processEnvelope, found
	}
	return nil, found
}

/********************* CONFIGURATION *********************/

// Config a simple configuration object
type Config struct {
	URL            string
	APIToken       string
	Verbose        bool
	Debug          bool
	GroupByProcess bool
}

// Parse reads configuration from arguments and environment
func (c *Config) Parse() *Config {
	flag.StringVar(&c.URL, "url", "", "the Dynatrace environment URL (e.g. https://####.live.dynatrace.com)")
	flag.StringVar(&c.APIToken, "token", "", "the API token to use for uploading configuration")
	flag.BoolVar(&c.Verbose, "verbose", false, "verbose logging")
	flag.BoolVar(&c.Debug, "debug", false, "prints out HTTP traffic")
	flag.BoolVar(&c.GroupByProcess, "groupByProcess", false, "group the output by process name and show all the vulnerable libraries in it")
	flag.Parse()
	c.URL = c.Lookup("DT_URL", c.URL)
	c.APIToken = c.Lookup("DT_TOKEN", c.APIToken)
	if len(c.URL) == 0 || len(c.APIToken) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	return c
}

// Lookup reads configuration from environment
func (c *Config) Lookup(envVar string, current string) string {
	if len(current) > 0 {
		return current
	}
	if v, found := os.LookupEnv(envVar); found {
		return v
	}
	return current
}

/********************* VARIABLE SUBSTITUTION *********************/
type variables map[string]string

func (vars variables) replace(o interface{}) interface{} {
	if o == nil {
		return nil
	}
	switch to := o.(type) {
	case string:
		if strings.HasPrefix(to, "{") && strings.HasSuffix(to, "}") {
			key := to[1 : len(to)-1]
			if value, found := vars[key]; found {
				return value
			}
		}
		return to
	case []interface{}:
		for i, v := range to {
			to[i] = vars.replace(v)
		}
		return to
	case map[string]interface{}:
		for k, v := range to {
			to[k] = vars.replace(v)
		}
		return to
	case int, int8, int32, int16, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
		return to
	default:
		panic(fmt.Sprintf("unsupported: %t", o))
	}
}

/********************* CONVENIENCE TYPES *********************/

// Endpoints is a convenience type for a map[string]string
// You can ask this object whether a specific file matches
// the prerequisites for the currently supported endpoint categories
type Endpoints map[string]string

// Contains returns true if an entry exist for this key, false otherwise
func (eps Endpoints) Contains(fileInfo os.FileInfo) bool {
	if fileInfo == nil || !fileInfo.IsDir() {
		return false
	}

	name := fileInfo.Name()

	if enforceLeadingDigits && !fileNameFormat.MatchString((name)) {
		return false
	}
	idx := strings.Index(name, "-")
	if idx >= 0 {
		name = name[idx+1:]
	}
	_, found := eps[name]
	return found
}

type SecurityProblemInfo struct {
	SecurityProblemId   string
	ExposedEntities     string
	CveIds              string
	ProcessInstanceId   string
	ProcessInstanceName string
	HostInstanceName    string
}

type ExposedEntityInfo struct {
	SecurityProblemId   string
	CveId               string
	ProcessInstanceId   string
	ProcessInstanceName string
	HostInstanceName    string
}

type LibrariesByProcess map[string]*Libraries

type Libraries struct {
	LibraryNames []string
}

type ProcessNames struct {
	ProcessInstanceNames []string
}
type ProcessesByLibrary map[string]*ProcessNames

type ProcessInstanceCache map[string]*ProcessEnvelope

/********************* API PAYLOAD *********************/

// ErrorEnvelope is potentially the JSON response code
// when a REST API call fails
type ErrorEnvelope struct {
	RESTError *RESTError `json:"error"` // the actual error object
}

func (e *ErrorEnvelope) Error() string {
	bytes, _ := json.MarshalIndent(e.RESTError, "", "  ")
	return string(bytes)
}

// RESTError is potentially the JSON response code
// when a REST API call fails
type RESTError struct {
	Code                 int                    `json:"code"`    // error code
	Message              string                 `json:"message"` // error message
	ConstraintViolations []*ConstraintViolation `json:"constraintViolations"`
}

func (e *RESTError) Error() string {
	bytes, _ := json.MarshalIndent(e, "", "  ")
	return string(bytes)
}

// ConstraintViolation is the viloation error
type ConstraintViolation struct {
	Path              string `json:"path"`
	Message           string `json:"message"`
	ParameterLocation string `json:"parameterLocation"`
	Location          string `json:"location"`
}

// SuccessEnvelope contains the successful response from the API endpoint
type SecurityProblemSuccessEnvelope struct {
	TotalCount       int               `json:"totalCount"`
	SecurityProblems []SecurityProblem `json:"securityProblems"`
}

// SecurityProblem has no documentation
type SecurityProblem struct {
	SecurityProblemId string `json:"securityProblemId"`
	Status            string `json:"status"`
}

// SecurityProblemInfoEnvelope contains the successful response from the API endpoint
type SecurityProblemInfoEnvelope struct {
	SecurityProblemId string `json:"securityProblemId"`
	//VulnerableComponents []*Library `json:"vulnerableComponents"`
	ExposedEntities []string `json:"exposedEntities"`
	CveIds          []string `json:"cveIds"`
}

// VulnerableComponent has no documentation
type Library struct {
	DisplayName         string   `json:"displayName"`
	VulnerableProcesses []string `json:"exposedEntities"`
	CveIds              []string `json:"cveIds"`
}

// ProcessEnvelope contains the successful response from the API endpoint
type ProcessEnvelope struct {
	EntityId          string       `json:"entityId"`
	DisplayName       string       `json:"displayName"`
	FromRelationships Relationship `json:"fromRelationships"`
}

type Relationship struct {
	IsProcessOf []string `json:"isProcessOf"`
}
