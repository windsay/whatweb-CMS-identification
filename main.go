package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

type HttpData struct {
	Url     string
	Headers map[string][]string
	Html    string
	Jsret   string
}

type analyzeData struct {
	scripts []string
	cookies map[string]string
}

type temp struct {
	Apps       map[string]*json.RawMessage `json:"apps"`
	Categories map[string]*json.RawMessage `json:"categories"`
}

type application struct {
	Name       string   `json:"name,ompitempty"`
	Version    string   `json:"version"`
	Categories []string `json:"categories,omitempty"`

	Cats     []int                  `json:"cats,omitempty"`
	Cookies  interface{}            `json:"cookies,omitempty"`
	Js       interface{}            `json:"js,omitempty"`
	Headers  interface{}            `json:"headers,omitempty"`
	HTML     interface{}            `json:"html,omitempty"`
	Excludes interface{}            `json:"excludes,omitempty"`
	Implies  interface{}            `json:"implies,omitempty"`
	Meta     map[string]interface{} `json:"meta,omitempty"`
	Scripts  interface{}            `json:"script,omitempty"`
	URL      string                 `json:"url,omitempty"`
	Website  string                 `json:"website,omitempty"`
}

type category struct {
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// Wappalyzer implements analyze method as original wappalyzer does
type Wappalyzer struct {
	HttpData   *HttpData
	Apps       map[string]*application
	Categories map[string]*category
	JSON       bool
}

var (
	cache = make(map[string]map[string]map[string][]*pattern)
	cacheLock sync.RWMutex
)

func getPatterns(app *application, typ string) map[string][]*pattern {
	cacheLock.RLock()
	defer cacheLock.RUnlock()
	return cache[app.Name][typ]
}

func initPatterns(app *application) {
	c := map[string]map[string][]*pattern{"url": parsePatterns0(app.URL)}
	if app.HTML != nil {
		c["html"] = parsePatterns0(app.HTML)
	}
	if app.Headers != nil {
		c["headers"] = parsePatterns0(app.Headers)
	}
	if app.Cookies != nil {
		c["cookies"] = parsePatterns0(app.Cookies)
	}
	if app.Scripts != nil {
		c["scripts"] = parsePatterns0(app.Scripts)
	}

	cacheLock.Lock()
	cache[app.Name] = c
	cacheLock.Unlock()
}

// Init
func Init(appsJSONPath string, JSON bool) (wapp *Wappalyzer, err error) {
	wapp = &Wappalyzer{}
	appsFile, err := ioutil.ReadFile(appsJSONPath)
	if err != nil {
		return nil, err
	}

	temporary := &temp{}
	err = json.Unmarshal(appsFile, &temporary)
	if err != nil {
		return nil, err
	}

	wapp.Apps = make(map[string]*application)
	wapp.Categories = make(map[string]*category)

	for k, v := range temporary.Categories {
		catg := &category{}
		if err = json.Unmarshal(*v, catg); err != nil {
			return nil, err
		}
		wapp.Categories[k] = catg
	}

	for k, v := range temporary.Apps {
		app := &application{}
		app.Name = k
		if err = json.Unmarshal(*v, app); err != nil {
			return nil, err
		}
		parseCategories(app, &wapp.Categories)
		initPatterns(app)
		wapp.Apps[k] = app
	}
	wapp.JSON = JSON

	return wapp, nil
}

func parseCategories(app *application, categories *map[string]*category) {
	for _, cat := range app.Cats {
		catStr := fmt.Sprintf("%d", cat)
		if catData, ok := (*categories)[catStr]; ok {
			app.Categories = append(app.Categories, catData.Name)
		}
	}
}

type resultApp struct {
	Name       string   `json:"name,ompitempty"`
	Version    string   `json:"version"`
	Categories []string `json:"categories,omitempty"`
	excludes   interface{}
	implies    interface{}
}

func (wapp *Wappalyzer) ConvHeader(headers string) map[string][]string {
	head := make(map[string][]string)

	tmp := strings.Split(strings.TrimRight(headers, "\n"), "\n")
	for _, v := range tmp {
		if strings.HasPrefix(strings.ToLower(v), "http/") {
			continue
		}
		splitStr := strings.Split(v, ":")
		header_key := strings.ToLower(strings.Replace(splitStr[0], "_", "-", -1))
		header_val := strings.TrimSpace(strings.Join(splitStr[1:], ""))

		head[header_key] = append(head[header_key], header_val)
	}

	return head
}
func analyzeURL(app *application, url string, detectedApplications *map[string]*resultApp) {
	patterns := getPatterns(app, "url")
	for _, v := range patterns {
		for _, pattrn := range v {
			if pattrn.regex != nil && pattrn.regex.MatchString(url) {
				if _, ok := (*detectedApplications)[app.Name]; !ok {
					resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
					(*detectedApplications)[resApp.Name] = resApp
					detectVersion(resApp, pattrn, &url)
				}
			}
		}
	}
}

func (wapp *Wappalyzer) Analyze(httpdata *HttpData) (result interface{}, err error) {
	analyzeData := &analyzeData{}
	detectedApplications := make(map[string]*resultApp)

	// analyze html script src
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(httpdata.Html))
	if err != nil {
		return nil, err
	}

	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		url, exists := s.Attr("src")
		if exists {
			analyzeData.scripts = append(analyzeData.scripts, url)
		}
	})

	// analyze headers cookie
	analyzeData.cookies = make(map[string]string)
	for _, cookie := range httpdata.Headers["set-cookie"] {
		keyValues := strings.Split(cookie, ";")
		for _, keyValueString := range keyValues {
			keyValueSlice := strings.Split(keyValueString, "=")
			if len(keyValueSlice) > 1 {
				key, value := keyValueSlice[0], keyValueSlice[1]
				analyzeData.cookies[key] = value
			}
		}
	}

	for _, app := range wapp.Apps {
		analyzeURL(app, httpdata.Url, &detectedApplications)
		if app.HTML != nil {
			analyzeHTML(app, httpdata.Html, &detectedApplications)
		}
		if app.Headers != nil {
			analyzeHeaders(app, httpdata.Headers, &detectedApplications)
		}
		if app.Cookies != nil {
			analyzeCookies(app, analyzeData.cookies, &detectedApplications)
		}
		if app.Scripts != nil {
			analyzeScripts(app, analyzeData.scripts, &detectedApplications)
		}
	}

	for _, app := range detectedApplications {
		if app.excludes != nil {
			resolveExcludes(&detectedApplications, app.excludes)
		}
		if app.implies != nil {
			resolveImplies(&wapp.Apps, &detectedApplications, app.implies)
		}
	}

	res := []map[string]interface{}{}
	for _, app := range detectedApplications {
		res = append(res, map[string]interface{}{"name": app.Name, "version": app.Version, "categories": app.Categories})
	}
	if wapp.JSON {
		j, err := json.Marshal(res)
		if err != nil {
			return nil, err
		}
		return string(j), nil
	}

	fmt.Println(httpdata.Url, res)

	return res, nil
}

type pattern struct {
	str        string
	regex      *regexp.Regexp
	version    string
	confidence string
}

func parsePatterns0(patterns interface{}) (result map[string][]*pattern) {
	parsed := make(map[string][]string)
	switch ptrn := patterns.(type) {
	case string:
		parsed["main"] = append(parsed["main"], ptrn)
	case map[string]interface{}:
		for k, v := range ptrn {
			parsed[k] = append(parsed[k], v.(string))
		}
	case []interface{}:
		var slice []string
		for _, v := range ptrn {
			slice = append(slice, v.(string))
		}
		parsed["main"] = slice
	default:
		return nil
	}
	result = make(map[string][]*pattern)
	for k, v := range parsed {
		for _, str := range v {
			appPattern := &pattern{}
			slice := strings.Split(str, "\\;")
			for i, item := range slice {
				if item == "" {
					continue
				}
				if i > 0 {
					additional := strings.Split(item, ":")
					if len(additional) > 1 {
						if additional[0] == "version" {
							appPattern.version = additional[1]
						} else {
							appPattern.confidence = additional[1]
						}
					}
				} else {
					appPattern.str = item
					first := strings.Replace(item, `\/`, `/`, -1)
					second := strings.Replace(first, `\\`, `\`, -1)
					reg, err := regexp.Compile(fmt.Sprintf("%s%s", "(?i)", strings.Replace(second, `/`, `\/`, -1)))
					if err == nil {
						appPattern.regex = reg
					}
				}
			}
			result[k] = append(result[k], appPattern)
		}
	}
	return result
}

func resolveExcludes(detectedApplications *map[string]*resultApp, excludes interface{}) {
	switch excls := excludes.(type) {
	case string:
		delete(*detectedApplications, excls)
	case []interface{}:
		for _, v := range excls {
			delete(*detectedApplications, v.(string))
		}
	}
}

func resolveImplies(apps *map[string]*application, detectedApplications *map[string]*resultApp, implies interface{}) {
	switch impls := implies.(type) {
	case string:
		app, ok := (*apps)[impls]
		if ok {
			if _, detected := (*detectedApplications)[app.Name]; !detected {
				resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
				(*detectedApplications)[resApp.Name] = resApp
			}
		}
	case []interface{}:
		for _, v := range impls {
			app, ok := (*apps)[v.(string)]
			if ok {
				if _, detected := (*detectedApplications)[app.Name]; !detected {
					resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
					(*detectedApplications)[resApp.Name] = resApp
				}
			}
		}
	}
}

func detectVersion(app *resultApp, pattrn *pattern, value *string) {
	versions := make(map[string]interface{})
	version := pattrn.version
	if slices := pattrn.regex.FindAllStringSubmatch(*value, -1); slices != nil {
		for _, slice := range slices {
			for i, match := range slice {
				reg, _ := regexp.Compile(fmt.Sprintf("%s%d%s", "\\\\", i, "\\?([^:]+):(.*)$"))
				ternary := reg.FindAll([]byte(version), -1)
				if ternary != nil && len(ternary) == 3 {
					version = strings.Replace(version, string(ternary[0]), string(ternary[1]), -1)
				}
				reg2, _ := regexp.Compile(fmt.Sprintf("%s%d", "\\\\", i))
				version = reg2.ReplaceAllString(version, match)
			}
		}
		if _, ok := versions[version]; ok != true && version != "" {
			versions[version] = struct{}{}
		}
		if len(versions) != 0 {
			for ver := range versions {
				if ver > app.Version {
					app.Version = ver
				}
			}
		}
	}
}

func analyzeHeaders(app *application, headers map[string][]string, detectedApplications *map[string]*resultApp) {
	patterns := getPatterns(app, "headers")
	for headerName, v := range patterns {
		headerNameLowerCase := strings.ToLower(headerName)

		for _, pattrn := range v {
			headersSlice, ok := headers[headerNameLowerCase]

			if !ok {
				continue
			}

			if ok && pattrn.regex == nil {
				resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
				(*detectedApplications)[resApp.Name] = resApp
			}

			if ok {
				for _, header := range headersSlice {
					if pattrn.regex != nil && pattrn.regex.Match([]byte(header)) {
						if _, ok := (*detectedApplications)[app.Name]; !ok {
							resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
							(*detectedApplications)[resApp.Name] = resApp
							detectVersion(resApp, pattrn, &header)
						}
					}
				}
			}
		}
	}
}

func analyzeHTML(app *application, html string, detectedApplications *map[string]*resultApp) {
	patterns := getPatterns(app, "html")
	for _, v := range patterns {
		for _, pattrn := range v {

			if pattrn.regex != nil && pattrn.regex.Match([]byte(html)) {
				if _, ok := (*detectedApplications)[app.Name]; !ok {
					resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
					(*detectedApplications)[resApp.Name] = resApp
					detectVersion(resApp, pattrn, &html)
				}
			}

		}
	}
}

func analyzeScripts(app *application, scripts []string, detectedApplications *map[string]*resultApp) {
	patterns := getPatterns(app, "scripts")
	for _, v := range patterns {
		for _, pattrn := range v {
			if pattrn.regex != nil {
				for _, script := range scripts {
					if pattrn.regex.Match([]byte(script)) {
						if _, ok := (*detectedApplications)[app.Name]; !ok {
							resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
							(*detectedApplications)[resApp.Name] = resApp
							detectVersion(resApp, pattrn, &script)
						}
					}
				}
			}
		}
	}
}

func analyzeCookies(app *application, cookies map[string]string, detectedApplications *map[string]*resultApp) {
	patterns := getPatterns(app, "cookies")
	for cookieName, v := range patterns {
		cookieNameLowerCase := strings.ToLower(cookieName)
		for _, pattrn := range v {
			cookie, ok := cookies[cookieNameLowerCase]

			if !ok {
				continue
			}

			if ok && pattrn.regex == nil {
				if _, ok := (*detectedApplications)[app.Name]; !ok {
					resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
					(*detectedApplications)[resApp.Name] = resApp
				}
			}

			if ok && pattrn.regex != nil && pattrn.regex.MatchString(cookie) {
				if _, ok := (*detectedApplications)[app.Name]; !ok {
					resApp := &resultApp{app.Name, app.Version, app.Categories, app.Excludes, app.Implies}
					(*detectedApplications)[resApp.Name] = resApp
					detectVersion(resApp, pattrn, &cookie)
				}
			}
		}
	}
}

type writeRequest struct {
	url    string
	result string
}

var wg sync.WaitGroup

func main() {
	file, err := os.Open("url.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	resultFile, err := os.OpenFile("result.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening result file:", err)
		return
	}
	defer resultFile.Close()

	wordpressFile, err := os.OpenFile("wordpress.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening WordPress file:", err)
		return
	}
	defer wordpressFile.Close()

	writeChan := make(chan writeRequest, 100)
	doneChan := make(chan bool)

	go func() {
		for req := range writeChan {
			if _, err := resultFile.WriteString(fmt.Sprintf("URL: %s\nResult: %s\n\n", req.url, req.result)); err != nil {
				fmt.Println("Error writing to result file:", err)
			}
			if strings.Contains(req.result, "WordPress") {
				if _, err := wordpressFile.WriteString(fmt.Sprintf("%s\n", req.url)); err != nil {
					fmt.Println("Error writing to WordPress file:", err)
				}
			}
		}
		doneChan <- true
	}()

	scanner := bufio.NewScanner(file)
	urls := []string{}
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			result := recognize(url)
			writeChan <- writeRequest{url, result}
		}(url)
	}

	wg.Wait()
	close(writeChan)
	<-doneChan

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
}

func recognize(url string) string {
	fmt.Println("Processing URL:", url)
	wapp, err := Init("app.json", true)
	if err != nil {
		fmt.Println("Error initializing Wappalyzer:", err)
		return ""
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error fetching URL %s: %v\n", url, err)
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body for URL %s: %v\n", url, err)
		return ""
	}

	headers := make(map[string][]string)
	for key, values := range resp.Header {
		headers[strings.ToLower(key)] = values
	}

	httpData := &HttpData{
		Url:     url,
		Headers: headers,
		Html:    string(body),
	}

	result, err := wapp.Analyze(httpData)
	if err != nil {
		fmt.Printf("Error analyzing URL %s: %v\n", url, err)
		return ""
	}

	fmt.Printf("Result for URL %s: %v\n", url, result)
	return fmt.Sprintf("%v", result)
}
