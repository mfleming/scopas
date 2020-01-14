// Copyright 2020 Matt Fleming.
//
// Use of this source code is governed by Apache 2 LICENSE that can be
// found in the LICENSE file.

// TODO
//
// - Go through bash file and check for missing checks/features and update this list
// - Need timestamps in stages output to correlate stages with metrics, e.g. mpstat.log
// - Use an optimised disk image on VM creation
// - Wire up SIGINT handler to destroy builder in case of Ctrl-C
// - Command-line arguments
// --update-image support
// - Download the kernel rpm file on success
// - Support multiple providers in the scopas config file
// - Versioning of disk images and updates when new features/optimisations are supported
// - Docker support to simplify building multiple architectures (crosstool, etc)
//
// DONE
// --stats support
// - Help for command-line arguments
// - Move all logs to ~/.scopas/logs/

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	//"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pborman/getopt"
	"golang.org/x/crypto/ssh"
)

type Flags struct {
	clean  bool
	debug  bool
	update bool
	stats  bool
	pkg    bool
}

var cfgFlags Flags

func debug(msg string, args ...interface{}) {
	if cfgFlags.debug == false {
		return
	}

	fmt.Printf("[DEBUG] "+msg+"\n", args...)
}

func log(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
}

func die(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

type CloudProviderConfig struct {
	Name       string
	API        string
	Instance   string
	SSHKeyPath string
	Region     string
	Volume     string
	Image      string
}

func parseSection(t string, p *CloudProviderConfig) error {
	switch t {
	case "[global]":
		fmt.Println("Found global section")
	case "[provider]":
		fmt.Println("Found provider section")
		p.Name = "Linode"
	default:
		return fmt.Errorf("unknown ini section: %s", t)
	}

	return nil
}

func parseProperty(t string, p *CloudProviderConfig) error {
	var slices []string
	slices = strings.Split(t, "=")

	if len(slices) != 2 {
		return fmt.Errorf("invalid property syntax")
	}

	keyword := slices[0]
	property := slices[1]

	if property == "" {
		return fmt.Errorf("missing property value")
	}

	switch keyword {
	case "API_TOKEN":
		p.API = property
	case "INSTANCE_TYPE":
		p.Instance = property
	case "BUILDER_NAME":
		p.Name = property
	case "INSTANCE_REGION":
		p.Region = property
	case "INSTANCE_IMAGE":
		p.Image = property
	case "INSTANCE_VOLUME":
		p.Volume = property
	case "SSH_KEY_PATH":
		p.SSHKeyPath = property
	default:
		return fmt.Errorf("unknown config option \"%s\"", keyword)
	}

	return nil
}

func ParseConfig(s string) (*CloudProviderConfig, error) {
	f, _ := os.Open(s)
	defer f.Close()

	var provider *CloudProviderConfig = new(CloudProviderConfig)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		t := scanner.Text()
		err := parseProperty(t, provider)
		if err != nil {
			return nil, err
		}
	}

	return provider, nil
}

type Instance struct {
	Id              float64                  `json:"id"`
	Label           string                   `json:"label"`
	Group           string                   `json:"group"`
	Status          string                   `json:"status"`
	Created         string                   `json:"created"`
	Updated         string                   `json:"updated"`
	Type            string                   `json:"type"`
	Ipv4            []string                 `json:"ipv4"`
	Ipv6            string                   `json:"ipv6"`
	Image           string                   `json:"image"`
	Region          string                   `json:"region"`
	Specs           map[string]interface{}   `json:"specs"`
	Alerts          map[string]interface{}   `json:"alerts"`
	Backups         map[string]interface{}   `json:"backups"`
	Hypervisor      string                   `json:"hypervisor"`
	WatchdogEnabled bool                     `json:"watchdog_enabled"`
	Tags            []string                 `json:"tags"`
	Errors          []map[string]interface{} `json:"errors"`
}

type Builder struct {
	Id       int
	Ipv4     string
	Client   *ssh.Client
	Instance *Instance
	Provider *CloudProviderConfig
}

func (builder *Builder) GetDistro() string {
	d := strings.Split(builder.Provider.Image, "/")[1]
	return d
}

// This function only returns once the builder is fully up and running.
// In other words, once it's finished provisioning and booting.
func (builder *Builder) Provision() {
	p := builder.Provider

	fmt.Println("(1/6) Provisioning builder")
	k, _ := ioutil.ReadFile(p.SSHKeyPath)
	// Trim newline
	key := strings.TrimSuffix(string(k), "\n")

	data := map[string]interface{}{"image": p.Image,
		"root_pass": "c001P455w0rd",
		"authorized_keys": []interface{}{
			string(key),
		},
		"booted": true,
		"label":  p.Name,
		"type":   p.Instance,
		"region": p.Region,
		"group":  "Linode-Group"}

	mData, _ := json.Marshal(data)
	d := doRequest(p, "https://api.linode.com/v4/linode/instances",
		"POST", mData)

	var instance Instance
	unmarshal(d, &instance)

	debug("Found %s (ID: %d) @ %s", instance.Label, int(instance.Id), instance.Ipv4[0])

	var tmpInstance Instance
	tmpInstance.Status = "provisioning"

	// Spin until the builder is fully initialised
	for tmpInstance.Status == "provisioning" ||
		tmpInstance.Status == "booting" {
		url := "https://api.linode.com/v4/linode/instances/" + strconv.Itoa(int(instance.Id))
		d = doRequest(p, url, "GET", nil)
		unmarshal(d, &tmpInstance)
		time.Sleep(2 * time.Second)
	}

	builder.Id = int(instance.Id)
	builder.Ipv4 = instance.Ipv4[0]
	builder.Instance = &instance
}

func (builder *Builder) WaitForSSH() {
	p := builder.Provider
	path := strings.TrimSuffix(p.SSHKeyPath, ".pub")

	privKey, err := ioutil.ReadFile(path)
	if err != nil {
		die("could not read SSH private key file: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privKey)
	if err != nil {
		die("could not parse SSH private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		Timeout: 1 * time.Second,
		// This is not a good idea in production
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// This is optimistic. It's possible to get stuck here forever
	// if the builder doesn't eventually come up.
	client, err := ssh.Dial("tcp", builder.Ipv4+":22", config)
	for err != nil {
		time.Sleep(2 * time.Second)
		client, err = ssh.Dial("tcp", builder.Ipv4+":22", config)
	}

	builder.Client = client
}

type LinodeConfig struct {
	id           string
	label        string
	kernel       string
	comments     string
	memory_limit float64
	run_level    string
	virt_mode    string
	helpers      map[string]interface{}
	//devices []
}

type LinodeProfile struct {
	data []LinodeConfig
}

func (builder *Builder) persist() {
	//p := builder.Provider
	//id := strconv.Itoa(builder.Id)
	//url := "https://api.linode.com/v4/linode/instances/"+id+"/configs",
	//d := doRequest(p, url, "GET", nil)
}

func (builder *Builder) Configure() {
	fmt.Println("(2/6) Configuring builder")

	runRemoteCmd(builder, "uname -r")

	debug("Cleaning old logs")
	runRemoteCmd(builder, "rm -fr /tmp/scopas/ ; mkdir -p /tmp/scopas/")

	// Mount volumes
	if builder.Provider.Volume != "" {
		mountVolume(builder)
	}

	runRemoteCmd(builder, "make --version")
	if strings.Contains(stderr.String(), "command not found") {
		debug("Installing packages")
		switch builder.GetDistro() {
		case "opensuse15.1":
			runRemoteCmd(builder, "zypper refresh && zypper -n install -y gcc bc "+
				"cpio git make flex bison patch libelf-devel "+
				"libopenssl-devel bc sysstat dpkg fakeroot rpmbuild ts | tee /tmp/scopas/install.log")
		case "ubuntu18.04":
			//runRemoteCmd(builder, "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y gcc bc "+
			//	"cpio git make flex bison patch libelf-dev")
			runRemoteCmd(builder, "DEBIAN_FRONTEND=noninteractive apt-get update")
			runRemoteCmd(builder, "DEBIAN_FRONTEND=noninteractive apt-get install -y libncurses-dev flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf git make gcc bc flex bison patch libelf-dev moreutils 2>&1 | tee /tmp/scopas/install.log")
		}
	}

	debug("Monitoring builder")

	runRemoteCmd(builder, "vmstat 1 | ts &> /tmp/scopas/vmstat.log &")
	runRemoteCmd(builder, "mpstat -P ALL 1 | ts &> /tmp/scopas/mpstat.log &")
	runRemoteCmd(builder, "iostat -xz 1 | ts &> /tmp/scopas/iostat.log &")
}

func (builder *Builder) RemoteGit() {
	// Check CWD for presence of .git directory and Kbuild file to make sure
	// that we're really inside a directory with the Linux kernel source.
	_, err1 := os.Stat(".git")
	_, err2 := os.Stat("Kbuild")
	if err1 == nil || err2 == nil {
		die("Not running inside git repository?")
	}

	err, outb := runLocalCmd("git rev-parse --abbrev-ref HEAD")
	if err != nil {
		die("couldn't execute git command")
	}

	localBranch := strings.TrimSuffix(outb.String(), "\n")

	s := fmt.Sprintf("git config branch.%s.remote", localBranch)
	err, outb = runLocalCmd(s)
	trackingRemote := strings.TrimSuffix(outb.String(), "\n")

	s = fmt.Sprintf("git config remote.%s.url", trackingRemote)
	err, outb = runLocalCmd(s)
	remoteUrl := strings.TrimSuffix(outb.String(), "\n")

	err, outb = runLocalCmd("git merge-base @{u} HEAD")
	localRef := strings.TrimSuffix(outb.String(), "\n")

	// Strip any protocol prefix from url
	sA := regexp.MustCompile("(http|git|ssh)://").Split(remoteUrl, 2)
	gitPath := sA[1]

	gitUrl := fmt.Sprintf("/mnt/scopas-vol/%s", gitPath)
	cmdString := fmt.Sprintf("[ -d %s ]", gitUrl)
	err = runRemoteCmd(builder, cmdString)
	if err != nil {
		debug("Creating mirror of git repository... This may take a few minutes")

		cmdString = fmt.Sprintf("cd /mnt/scopas-vol && mkdir -p %s && cd %s && git clone --mirror %s | tee /tmp/scopas/git-mirror.log", gitPath, remoteUrl)
		runRemoteCmd(builder, cmdString)
	}

	// TODO This needs fixing because we're not actually using these commits yet
	debug("Pushing latest git commits")

	runShellScript("#!/bin/bash\nGIT_SSH_COMMAND=\"/usr/bin/ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=1 -o LogLevel=QUIET -i %s\" /usr/bin/git push --quiet --force ssh://root@%s:%s\n", builder.Provider.SSHKeyPath, builder.Ipv4, gitUrl)

	s = fmt.Sprintf("(3/6) Cloning git repository and setting HEAD @ %s", localRef)
	log(s)

	cmdString = fmt.Sprintf("mkdir /dev/shm/build && cd /dev/shm/build && git clone %s kernel && cd /dev/shm/build/kernel && git reset --hard %s | tee /tmp/scopas/git-clone.log", gitUrl, localRef)
	runRemoteCmd(builder, cmdString)
}

func (builder *Builder) RemoteBuild() {
	log("(5/6) Building kernel")

	target := "all modules"

	// Build .deb or .rpm packages?
	if cfgFlags.pkg {
		switch builder.GetDistro() {
		case "opensuse15.1":
			target = "binrpm-pkg"
		case "ubuntu18.04":
			target = "bindeb-pkg"
		}
	}

	cmd := fmt.Sprintf("cd /dev/shm/build/kernel && make defconfig && make -j`nproc` %s | ts | tee /tmp/scopas/build.log", target)
	runRemoteCmd(builder, cmd)
}

func (builder *Builder) FetchLogs() {
	debug("Fetching results and monitoring logs")

	d := fmt.Sprintf("%s/.scopas/logs/%s", os.ExpandEnv("$HOME"), time.Now().Format(time.RFC3339))
	if err := os.MkdirAll(d, 0755); err != nil {
		die("Failed to create logs directory")
	}

	runRemoteCmd(builder, "systemd-analyze blame &> /tmp/scopas/systemd-analyze-blame.log")
	runRemoteCmd(builder, "systemd-analyze critical-chain &> /tmp/scopas/systemd-analyze-critical-chain.log")

	runShellScript("#!/bin/bash\n/usr/bin/scp -i %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ConnectTimeout=1 root@%s:/tmp/scopas/*.log %s\n", builder.Provider.SSHKeyPath, builder.Ipv4, d)
}

func (builder *Builder) Destroy() {
	p := builder.Provider
	stringId := strconv.Itoa(builder.Id)
	url := "https://api.linode.com/v4/linode/instances/" + stringId + "/shutdown"
	d := doRequest(p, url, "POST", nil)

	for {
		d = doRequest(p, url, "POST", nil)

		// Wait for the JSON response to be empty
		if len(string(d)) == len("{}") {
			break
		}

		time.Sleep(2 * time.Second)
	}

	debug("Deleting builder")
	url = "https://api.linode.com/v4/linode/instances/" + stringId
	doRequest(p, url, "DELETE", nil)
}

func makeRequest(p *CloudProviderConfig, url string, method string, data []byte) *http.Request {

	debug("HTTP %s -> %s", method, url)
	req, _ := http.NewRequest(method, url, bytes.NewBuffer(data))

	var bearer = "Bearer " + p.API
	req.Header.Add("Authorization", bearer)

	if data != nil {
		req.Header.Add("Content-type", "application/json")
	}

	return req
}

func doRequest(p *CloudProviderConfig, url string, method string, data []byte) []byte {

	req := makeRequest(p, url, method, data)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		die("The %s call failed with %s", method, err)
	}

	d, _ := ioutil.ReadAll(resp.Body)
	return d
}

func unmarshal(data []byte, instance *Instance) {
	err := json.Unmarshal(data, instance)
	if err != nil {
		die("Failed to unmarshla JSON: %s", err)
	}
}

var stdout, stderr bytes.Buffer

// Execute a command on a remote host over SSH
func runRemoteCmd(builder *Builder, cmd string) error {
	client := builder.Client
	session, err := client.NewSession()
	if err != nil {
		die("failed to create SSH session: %v", err)
	}

	// Do not carry over output from previous command
	stdout.Reset()
	stderr.Reset()

	session.Stdout = &stdout
	session.Stderr = &stderr

	debug("remotely executing: \"%s\"", cmd)
	err = session.Run(cmd)
	//	if err := session.Run(cmd); err != nil {
	//		die("failed to run command: %v\n\"%s\"", err, stderr.String())
	//	}

	defer session.Close()

	return err
}

func mountVolume(builder *Builder) {
	type ConfigId struct {
		Id float64 `json:"id"`
	}

	type Config struct {
		Data []ConfigId `json:"data"`
	}

	url := "https://api.linode.com/v4/volumes"
	d := doRequest(builder.Provider, url, "GET", nil)

	var c Config
	err := json.Unmarshal(d, &c)
	if err != nil {
		die("unable to unmarshal JSON data")
	}

	volumeId := int(c.Data[0].Id)

	url = "https://api.linode.com/v4/linode/instances/" + strconv.Itoa(builder.Id) + "/configs"
	d = doRequest(builder.Provider, url, "GET", nil)

	err = json.Unmarshal(d, &c)
	if err != nil {
		die("unable to unmarshal JSON data")
	}

	configId := int(c.Data[0].Id)

	data := map[string]interface{}{
		"linode_id": builder.Id,
		"config_id": configId,
	}

	mData, _ := json.Marshal(data)
	url = "https://api.linode.com/v4/volumes/" + strconv.Itoa(volumeId) + "/attach"
	d = doRequest(builder.Provider, url, "POST", mData)

	runRemoteCmd(builder, "grep scopas-vol /etc/fstab")
	if len(stdout.String()) == 0 {
		debug("Adding storage volume to /etc/fstab")
		runRemoteCmd(builder, "mkdir -p /mnt/scopas-vol")
		runRemoteCmd(builder, "echo '/dev/disk/by-id/scsi-0Linode_Volume_scopas-vol /mnt/scopas-vol ext4 defaults,noatime,nofail,data=writeback,barrier=0 0 2' >> /etc/fstab")
		runRemoteCmd(builder, "cat /etc/fstab")
	}

	debug("Mounting volume")
	runRemoteCmd(builder, "mount /mnt/scopas-vol")

	// Spin until disk appears
	runRemoteCmd(builder, "df -h / | tail -n1 | awk '{print $1}'")
	rootDev := strings.TrimSuffix(stdout.String(), "\n")

	cmd := fmt.Sprintf("df -h /mnt/scopas-vol | grep %s", rootDev)
	runRemoteCmd(builder, cmd)

	for len(stdout.String()) > 0 {
		runRemoteCmd(builder, "mount /mnt/scopas-vol")
		runRemoteCmd(builder, cmd)
		time.Sleep(2 * time.Second)
	}

	runRemoteCmd(builder, "df -h /mnt/scopas-vol")
}

func runLocalCmd(cmd string) (error, bytes.Buffer) {
	debug("locally executing: \"%s\"", cmd)
	a := strings.Split(cmd, " ")

	c := exec.Command(a[0], a[1:]...)

	var outb, errb bytes.Buffer
	c.Stdout = &outb
	c.Stderr = &errb

	err := c.Run()
	if err != nil {
		fmt.Println(outb.String())
		fmt.Println(errb.String())
		fmt.Printf("couldn't exec command: %v\n", err)
	}

	return err, outb
}

// Go's handling of env variables with spaces and double quotes makes it
// impossible to do this kind of stuff natively.
func runShellScript(s string, args ...interface{}) {
	content := fmt.Sprintf(s, args...)

	f, err := ioutil.TempFile("", "scopas.sh.")
	if err != nil {
		die("Failed to create shell script file: %v", err)
	}

	f.Chmod(0755)
	f.WriteString(content)
	f.Close()

	runLocalCmd(f.Name())

	defer os.Remove(f.Name())
}

type StageStats struct {
	duration time.Duration
	name     string
}

var totalTime time.Duration

func printStats() {
	fmt.Printf("\nStatistics:\n===========\n\n")

	fmt.Printf("Total time: %s\n\n", totalTime.Round(time.Second))

	for i, s := range stages {
		fmt.Printf("Step %d (%s): %s\n", i+1, s.name, s.duration.Round(time.Second))
	}
}

func parseArgs() {
	c := getopt.BoolLong("clean", 'c', "Do not use a custom VM image if one is available")
	d := getopt.BoolLong("debug", 'd', "Enable debug output")
	u := getopt.BoolLong("update", 'u', "Update (or create) an optimised VM image")
	x := getopt.BoolLong("stats", 's', "Print various statistics including duration of steps")
	h := getopt.BoolLong("help", 'h', "Display this help text and exit")
	p := getopt.BoolLong("package", 'p', "Build kernel rpm or deb packages along with perf-tools")
	getopt.Parse()

	if *h {
		fmt.Fprintf(os.Stderr, "scopas - Linux kernel build tool\n\n")
		getopt.Usage()
		os.Exit(0)
	}

	cfgFlags.clean = *c
	cfgFlags.debug = *d
	cfgFlags.update = *u
	cfgFlags.stats = *x
	cfgFlags.pkg = *p
}

var start = time.Now()
var stages []StageStats

func timer(n string, f func()) {
	defer endStep(n, time.Now())
	f()
}

func endStep(n string, start time.Time) {
	d := time.Since(start)

	var s StageStats
	s.duration = d
	s.name = n

	stages = append(stages, s)

}

func main() {
	parseArgs()

	// FIXME Check return val
	provider, _ := ParseConfig("/home/matt/.scopas/config")

	builder := new(Builder)
	builder.Provider = provider

	start := time.Now()

	timer("provision", builder.Provision)
	timer("ssh", builder.WaitForSSH)
	timer("configure", builder.Configure)
	timer("git", builder.RemoteGit)
	timer("build", builder.RemoteBuild)
	timer("logs", builder.FetchLogs)
	timer("destroy", builder.Destroy)

	totalTime = time.Since(start)

	if cfgFlags.stats {
		printStats()
	}
}
