package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type MemoryRegion struct {
	StartAddr int64
	EndAddr   int64
	Size      int64
	Name      string
}

type SecretPattern struct {
	Name  string
	Regex *regexp.Regexp
}

type ScanResult struct {
	PID         string `json:"pid"`
	ProcessName string `json:"process_name"`
	Type        string `json:"type"`
	Region      string `json:"region"`
	Offset      string `json:"offset"`
	Match       string `json:"match"`
}

var patterns = []SecretPattern{
	{Name: "Google API Key", Regex: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`)},
	{Name: "Slack Token", Regex: regexp.MustCompile(`xox[bapr]-[0-9A-Za-z-]{10,48}`)},
	{Name: "Generic Bearer Token", Regex: regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`)},
	{Name: "Private Key Header", Regex: regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`)},
	{Name: "AWS Access Key ID", Regex: regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`)},
	{Name: "AWS Secret Access Key", Regex: regexp.MustCompile(`(?i)aws_(?:secret|key|secret_key).{0,20}['"‘“][0-9a-zA-Z\/+]{40}['"’ ”]`)},
	{Name: "GitHub Access Token", Regex: regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`)},
	{Name: "JSON Web Token (JWT)", Regex: regexp.MustCompile(`\b(eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+)\b`)},
	{Name: "Discord Bot Token", Regex: regexp.MustCompile(`\b([a-zA-Z0-9-_]{24,26}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27,38})\b`)},
	{Name: "Stripe API Key", Regex: regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34})\b`)},
	{Name: "Twilio Account SID", Regex: regexp.MustCompile(`\b(AC[0-9a-fA-F]{32})\b`)},
	{Name: "Twilio Auth Token", Regex: regexp.MustCompile(`\b([0-9a-fA-F]{32})\b`)},
	{Name: "GCP Service Account", Regex: regexp.MustCompile(`"type":\s*"service_account"`)},
	{Name: "Heroku API Key", Regex: regexp.MustCompile(`(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)},
	{Name: "Facebook Access Token", Regex: regexp.MustCompile(`(?i)EAACEdEose0cBA[0-9A-Za-z]+`)},
	{Name: "PuTTY Private Key", Regex: regexp.MustCompile(`PuTTY-User-Key-File-2`)},
	{Name: "Database Connection String", Regex: regexp.MustCompile(`(?i)(mongodb|postgres|mysql|sqlite):\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+:[0-9]+`)},
}

var allResults []ScanResult

func getProcessName(pid string) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func findPIDByName(name string) ([]string, error) {
	var pids []string
	matches, err := filepath.Glob("/proc/[0-9]*/comm")
	if err != nil {
		return nil, err
	}

	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		commName := strings.TrimSpace(string(data))
		if strings.Contains(strings.ToLower(commName), strings.ToLower(name)) {
			parts := strings.Split(path, "/")
			if len(parts) >= 3 {
				pids = append(pids, parts[2])
			}
		}
	}
	return pids, nil
}

func findAllPIDs() ([]string, error) {
	var pids []string

	matches, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, err
	}

	for _, path := range matches {
		pid := filepath.Base(path)
		pids = append(pids, pid)
	}
	return pids, nil
}

func parseMemoryMaps(pid string) ([]MemoryRegion, error) {
	mapsPath := fmt.Sprintf("/proc/%s/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var regions []MemoryRegion
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "rw-p") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addrRange := strings.Split(fields[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		var start, end int64
		_, errStart := fmt.Sscanf(addrRange[0], "%x", &start)
		_, errEnd := fmt.Sscanf(addrRange[1], "%x", &end)
		if errStart != nil || errEnd != nil {
			continue
		}
		name := "anonymous"
		if len(fields) >= 6 {
			name = fields[5]
		}
		regions = append(regions, MemoryRegion{
			StartAddr: start,
			EndAddr:   end,
			Size:      end - start,
			Name:      name,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("Error while reading map: %w", err)
	}
	return regions, nil
}

func scanBuffer(buffer []byte, regionName string, startAddr int64) {
	for _, pattern := range patterns {
		matches := pattern.Regex.FindAll(buffer, -1)
		for _, match := range matches {
			cleanMatch := bytes.TrimSpace(match)
			if len(cleanMatch) > 0 {
				fmt.Printf("[!] Alert: Found %s in region %s (Offset: 0x%x)\n", pattern.Name, regionName, startAddr)
				fmt.Printf("    -> Match: %s\n\n", string(cleanMatch))
			}
		}
	}
}

func main() {
	targetFlag := flag.String("t", "", "Target process name to scan for secrets")
	pidFlag := flag.String("p", "", "Target process PID to scan for secrets")
	allFlag := flag.Bool("a", false, "Scan all running processes for secrets")
	outputFlag := flag.String("o", "", "Output file to save results in JSON format")
	flag.Parse()

	var targetPIDs []string
	var err error

	if *targetFlag != "" {
		fmt.Printf("[*] Searching process with name: %s\n", *targetFlag)
		targetPIDs, err = findPIDByName(*targetFlag)
		if err != nil {
			fmt.Printf("[-] No running process matches the name: %s\n", *targetFlag)
			return
		}
	} else if *pidFlag != "" {
		targetPIDs = []string{*pidFlag}
	} else if *allFlag {
		targetPIDs, err = findAllPIDs()
		if err != nil {
			fmt.Printf("[-] Error occurred while finding all PIDs: %v\n", err)
			return
		}
		fmt.Printf("[+] Found %d active processes to analyze.\n", len(targetPIDs))
	} else {
		fmt.Println("Usage: sudo memchk [-t <process_name> | -p <pid> | -a | -o <name.json>]")
		return
	}

	for _, pid := range targetPIDs {
		fmt.Printf("[+] Starting memory analysis for PID %s...\n", pid)
		regions, err := parseMemoryMaps(pid)
		if err != nil {
			fmt.Printf("[-] Error occurred while parsing memory maps for PID %s\n", pid)
			continue
		}

		memPath := fmt.Sprintf("/proc/%s/mem", pid)
		memFile, err := os.Open(memPath)
		if err != nil {
			continue
		}
		for _, region := range regions {
			if region.Size > 50*1024*1024 {
				continue
			}
			buffer := make([]byte, region.Size)
			_, err := memFile.ReadAt(buffer, region.StartAddr)
			if err != nil && err != io.EOF {
				continue
			}
			if len(buffer) > 0 {
				scanBuffer(buffer, region.Name, region.StartAddr)
			}
		}
		memFile.Close()
	}
	fmt.Println("[*] Scan is done")
	if *outputFlag != "" {
		fmt.Printf("[*] Exporting %d results to %s...\n", len(allResults), *outputFlag)
		jsonData, err := json.MarshalIndent(allResults, "", "  ")
		if err != nil {
			fmt.Printf("[-] Error formatting JSON: %v\n", err)
			return
		}
		err = os.WriteFile(*outputFlag, jsonData, 0644)
		if err != nil {
			fmt.Printf("[-] Error writing file: %v\n", err)
			return
		}
		fmt.Println("[+] Export succesful!")
	}
}
