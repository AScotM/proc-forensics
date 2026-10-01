package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "1.0.1"

type Config struct {
	JSON        bool
	ProcRoot    string
	ShowEnv     bool
	ShowMaps    bool
	ShowFDs     bool
	ShowThreads bool
	Version     bool
	PID         int
}

type Identity struct {
	PID          int    `json:"pid"`
	PPID         int    `json:"ppid"`
	TGID         int    `json:"tgid"`
	Name         string `json:"name"`
	State        string `json:"state"`
	UIDReal      uint64 `json:"uid_real"`
	UIDEffective uint64 `json:"uid_effective"`
	UIDSaved     uint64 `json:"uid_saved"`
	UIDFS        uint64 `json:"uid_fs"`
	GIDReal      uint64 `json:"gid_real"`
	GIDEffective uint64 `json:"gid_effective"`
	GIDSaved     uint64 `json:"gid_saved"`
	GIDFS        uint64 `json:"gid_fs"`
	User         string `json:"user"`
	Group        string `json:"group"`
	Executable   string `json:"executable"`
	CWD          string `json:"cwd"`
	Root         string `json:"root"`
	Command      string `json:"command"`
}

type CPUInfo struct {
	UserTicks      uint64  `json:"user_ticks"`
	SystemTicks    uint64  `json:"system_ticks"`
	ChildrenUser   int64   `json:"children_user_ticks"`
	ChildrenSystem int64   `json:"children_system_ticks"`
	StartTicks     uint64  `json:"start_ticks"`
	Priority       int64   `json:"priority"`
	Nice           int64   `json:"nice"`
	Processor      int64   `json:"processor"`
	Policy         int64   `json:"policy"`
	Threads        int64   `json:"threads"`
	VoluntaryCS    uint64  `json:"voluntary_context_switches"`
	InvoluntaryCS  uint64  `json:"involuntary_context_switches"`
	AllowedCPUs    string  `json:"allowed_cpus"`
	AllowedCPUList string  `json:"allowed_cpu_list"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
}

type MemoryInfo struct {
	VirtualBytes      uint64 `json:"virtual_bytes"`
	ResidentBytes     uint64 `json:"resident_bytes"`
	SharedBytes       uint64 `json:"shared_bytes"`
	DataBytes         uint64 `json:"data_bytes"`
	StackBytes        uint64 `json:"stack_bytes"`
	ExecutableBytes   uint64 `json:"executable_bytes"`
	LibraryBytes      uint64 `json:"library_bytes"`
	SwapBytes         uint64 `json:"swap_bytes"`
	PeakVirtualBytes  uint64 `json:"peak_virtual_bytes"`
	PeakResidentBytes uint64 `json:"peak_resident_bytes"`
	AnonymousBytes    uint64 `json:"anonymous_bytes"`
	HugeTLBBytes      uint64 `json:"hugetlb_bytes"`
}

type IOInfo struct {
	ReadSyscalls   uint64 `json:"read_syscalls"`
	WriteSyscalls  uint64 `json:"write_syscalls"`
	ReadBytes      uint64 `json:"read_bytes"`
	WriteBytes     uint64 `json:"write_bytes"`
	CancelledWrite uint64 `json:"cancelled_write_bytes"`
	RChar          uint64 `json:"rchar"`
	WChar          uint64 `json:"wchar"`
}

type SecurityInfo struct {
	Seccomp         int      `json:"seccomp"`
	SeccompFilters  int      `json:"seccomp_filters"`
	NoNewPrivileges bool     `json:"no_new_privileges"`
	CapInheritable  string   `json:"cap_inheritable"`
	CapPermitted    string   `json:"cap_permitted"`
	CapEffective    string   `json:"cap_effective"`
	CapBounding     string   `json:"cap_bounding"`
	CapAmbient      string   `json:"cap_ambient"`
	SELinuxContext  string   `json:"selinux_context"`
	TracerPID       int      `json:"tracer_pid"`
	CoreDumping     bool     `json:"core_dumping"`
	Speculation     []string `json:"speculation,omitempty"`
}

type NamespaceInfo struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	Inode  uint64 `json:"inode"`
}

type CgroupInfo struct {
	HierarchyID string   `json:"hierarchy_id"`
	Controllers []string `json:"controllers"`
	Path        string   `json:"path"`
}

type FDInfo struct {
	FD     int    `json:"fd"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

type FDSummary struct {
	Total       int      `json:"total"`
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	Sockets     int      `json:"sockets"`
	Pipes       int      `json:"pipes"`
	AnonInodes  int      `json:"anon_inodes"`
	Other       int      `json:"other"`
	LimitSoft   uint64   `json:"limit_soft"`
	LimitHard   uint64   `json:"limit_hard"`
	Entries     []FDInfo `json:"entries,omitempty"`
}

type SocketInfo struct {
	FD       int    `json:"fd"`
	Inode    uint64 `json:"inode"`
	Protocol string `json:"protocol"`
	Local    string `json:"local,omitempty"`
	Remote   string `json:"remote,omitempty"`
	State    string `json:"state,omitempty"`
}

type ThreadInfo struct {
	TID   int    `json:"tid"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type MapSummary struct {
	Regions     int      `json:"regions"`
	Executable  int      `json:"executable_regions"`
	Writable    int      `json:"writable_regions"`
	Anonymous   int      `json:"anonymous_regions"`
	FileBacked  int      `json:"file_backed_regions"`
	Deleted     int      `json:"deleted_regions"`
	UniqueFiles int      `json:"unique_files"`
	Files       []string `json:"files,omitempty"`
}

type EnvironmentInfo struct {
	Count     int               `json:"count"`
	Variables map[string]string `json:"variables,omitempty"`
}

type LimitsInfo struct {
	OpenFilesSoft uint64 `json:"open_files_soft"`
	OpenFilesHard uint64 `json:"open_files_hard"`
	ProcessesSoft uint64 `json:"processes_soft"`
	ProcessesHard uint64 `json:"processes_hard"`
	LockedSoft    uint64 `json:"locked_memory_soft"`
	LockedHard    uint64 `json:"locked_memory_hard"`
	AddressSoft   uint64 `json:"address_space_soft"`
	AddressHard   uint64 `json:"address_space_hard"`
}

type ProcessDossier struct {
	Version      string          `json:"version"`
	Timestamp    string          `json:"timestamp"`
	Hostname     string          `json:"hostname"`
	Kernel       string          `json:"kernel"`
	Architecture string          `json:"architecture"`
	Identity     Identity        `json:"identity"`
	CPU          CPUInfo         `json:"cpu"`
	Memory       MemoryInfo      `json:"memory"`
	IO           IOInfo          `json:"io"`
	Security     SecurityInfo    `json:"security"`
	Namespaces   []NamespaceInfo `json:"namespaces"`
	Cgroups      []CgroupInfo    `json:"cgroups"`
	FDs          FDSummary       `json:"file_descriptors"`
	Sockets      []SocketInfo    `json:"sockets"`
	Threads      []ThreadInfo    `json:"threads,omitempty"`
	Maps         MapSummary      `json:"memory_maps"`
	Environment  EnvironmentInfo `json:"environment"`
	Limits       LimitsInfo      `json:"limits"`
	Warnings     []string        `json:"warnings,omitempty"`
}

type StatusData struct {
	Values map[string]string
}

type StatData struct {
	PPID           int
	UserTicks      uint64
	SystemTicks    uint64
	ChildrenUser   int64
	ChildrenSystem int64
	Priority       int64
	Nice           int64
	Threads        int64
	StartTicks     uint64
	Processor      int64
	Policy         int64
}

type SocketRecord struct {
	Protocol string
	Local    string
	Remote   string
	State    string
	Inode    uint64
}

func main() {
	config, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if config.Version {
		fmt.Printf("proc-forensics %s\n", version)
		return
	}

	dossier, err := inspectProcess(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	if config.JSON {
		if err := printJSON(dossier); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return
	}

	printHuman(dossier)
}

func parseFlags() (Config, error) {
	var config Config

	flag.BoolVar(&config.JSON, "json", false, "")
	flag.StringVar(&config.ProcRoot, "proc", "/proc", "")
	flag.BoolVar(&config.ShowEnv, "env", false, "")
	flag.BoolVar(&config.ShowMaps, "maps", false, "")
	flag.BoolVar(&config.ShowFDs, "fds", false, "")
	flag.BoolVar(&config.ShowThreads, "threads", false, "")
	flag.BoolVar(&config.Version, "version", false, "")

	flag.Usage = func() {
		name := filepath.Base(os.Args[0])

		fmt.Fprintf(os.Stderr, "proc-forensics %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [OPTIONS] PID\n", name)
		fmt.Fprintf(os.Stderr, "  %s [OPTIONS] self\n\n", name)
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --json       Output JSON\n")
		fmt.Fprintf(os.Stderr, "  --env        Include environment variable values\n")
		fmt.Fprintf(os.Stderr, "  --maps       Include mapped file names\n")
		fmt.Fprintf(os.Stderr, "  --fds        Include individual file descriptors\n")
		fmt.Fprintf(os.Stderr, "  --threads    Include individual thread details\n")
		fmt.Fprintf(os.Stderr, "  --proc PATH  Alternate procfs root\n")
		fmt.Fprintf(os.Stderr, "  --version    Show version\n")
		fmt.Fprintf(os.Stderr, "  --help       Show help\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s 1\n", name)
		fmt.Fprintf(os.Stderr, "  %s self\n", name)
		fmt.Fprintf(os.Stderr, "  %s --json 1234\n", name)
		fmt.Fprintf(os.Stderr, "  %s --fds --threads 1234\n", name)
		fmt.Fprintf(os.Stderr, "  %s --maps --env 1234\n", name)
	}

	flag.Parse()

	if config.Version {
		return config, nil
	}

	if flag.NArg() != 1 {
		return config, errors.New("exactly one PID or 'self' is required")
	}

	target := strings.TrimSpace(flag.Arg(0))

	if target == "self" {
		config.PID = os.Getpid()
	} else {
		pid, err := strconv.Atoi(target)
		if err != nil || pid <= 0 {
			return config, fmt.Errorf("invalid PID: %s", target)
		}
		config.PID = pid
	}

	if config.ProcRoot == "" {
		return config, errors.New("procfs root cannot be empty")
	}

	return config, nil
}

func inspectProcess(config Config) (ProcessDossier, error) {
	var dossier ProcessDossier

	processRoot := filepath.Join(config.ProcRoot, strconv.Itoa(config.PID))

	if _, err := os.Stat(processRoot); err != nil {
		if os.IsNotExist(err) {
			return dossier, fmt.Errorf("process %d does not exist", config.PID)
		}
		return dossier, fmt.Errorf("cannot access process %d: %w", config.PID, err)
	}

	status, err := readStatus(filepath.Join(processRoot, "status"))
	if err != nil {
		return dossier, fmt.Errorf("cannot read process status: %w", err)
	}

	stat, err := readStat(filepath.Join(processRoot, "stat"))
	if err != nil {
		return dossier, fmt.Errorf("cannot read process stat: %w", err)
	}

	hostname, _ := os.Hostname()
	kernel := readTrimmed(filepath.Join(config.ProcRoot, "sys", "kernel", "osrelease"))

	dossier.Version = version
	dossier.Timestamp = time.Now().Format(time.RFC3339)
	dossier.Hostname = fallback(hostname, "unknown")
	dossier.Kernel = fallback(kernel, "unknown")
	dossier.Architecture = runtime.GOARCH

	dossier.Identity = buildIdentity(config, status, stat)
	dossier.CPU = buildCPU(config, status, stat)
	dossier.Memory = buildMemory(status)

	if ioInfo, err := readIO(filepath.Join(processRoot, "io")); err == nil {
		dossier.IO = ioInfo
	} else {
		dossier.Warnings = append(dossier.Warnings, "process I/O counters unavailable: "+err.Error())
	}

	dossier.Security = buildSecurity(processRoot, status)

	if namespaces, err := readNamespaces(filepath.Join(processRoot, "ns")); err == nil {
		dossier.Namespaces = namespaces
	} else {
		dossier.Warnings = append(dossier.Warnings, "namespace information unavailable: "+err.Error())
	}

	if cgroups, err := readCgroups(filepath.Join(processRoot, "cgroup")); err == nil {
		dossier.Cgroups = cgroups
	} else {
		dossier.Warnings = append(dossier.Warnings, "cgroup information unavailable: "+err.Error())
	}

	fdSummary, fdInodes, err := readFDs(processRoot, config.ShowFDs)
	if err == nil {
		dossier.FDs = fdSummary
	} else {
		dossier.Warnings = append(dossier.Warnings, "file descriptors unavailable: "+err.Error())
	}

	if limits, err := readLimits(filepath.Join(processRoot, "limits")); err == nil {
		dossier.Limits = limits
		if dossier.FDs.LimitSoft == 0 {
			dossier.FDs.LimitSoft = limits.OpenFilesSoft
			dossier.FDs.LimitHard = limits.OpenFilesHard
		}
	} else {
		dossier.Warnings = append(dossier.Warnings, "resource limits unavailable: "+err.Error())
	}

	if len(fdInodes) > 0 {
		if sockets, err := readSockets(processRoot, fdInodes); err == nil {
			dossier.Sockets = sockets
		} else {
			dossier.Warnings = append(dossier.Warnings, "socket details partially unavailable: "+err.Error())
		}
	}

	if threads, err := readThreads(processRoot, config.ShowThreads); err == nil {
		dossier.Threads = threads
	} else {
		dossier.Warnings = append(dossier.Warnings, "thread details unavailable: "+err.Error())
	}

	if maps, err := readMaps(filepath.Join(processRoot, "maps"), config.ShowMaps); err == nil {
		dossier.Maps = maps
	} else {
		dossier.Warnings = append(dossier.Warnings, "memory maps unavailable: "+err.Error())
	}

	if environment, err := readEnvironment(filepath.Join(processRoot, "environ"), config.ShowEnv); err == nil {
		dossier.Environment = environment
	} else {
		dossier.Warnings = append(dossier.Warnings, "environment unavailable: "+err.Error())
	}

	sort.Strings(dossier.Warnings)

	return dossier, nil
}

func readStatus(path string) (StatusData, error) {
	status := StatusData{
		Values: make(map[string]string),
	}

	file, err := os.Open(path)
	if err != nil {
		return status, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		index := strings.IndexByte(line, ':')
		if index < 0 {
			continue
		}

		key := strings.TrimSpace(line[:index])
		value := strings.TrimSpace(line[index+1:])
		status.Values[key] = value
	}

	return status, scanner.Err()
}

func readStat(path string) (StatData, error) {
	var stat StatData

	data, err := os.ReadFile(path)
	if err != nil {
		return stat, err
	}

	line := strings.TrimSpace(string(data))
	closeParen := strings.LastIndex(line, ")")

	if closeParen < 0 || closeParen+2 >= len(line) {
		return stat, errors.New("malformed stat file")
	}

	fields := strings.Fields(line[closeParen+2:])

	if len(fields) < 39 {
		return stat, errors.New("stat file contains too few fields")
	}

	stat.PPID = parseInt(fields[1])
	stat.UserTicks = parseUint(fields[11])
	stat.SystemTicks = parseUint(fields[12])
	stat.ChildrenUser = parseInt64(fields[13])
	stat.ChildrenSystem = parseInt64(fields[14])
	stat.Priority = parseInt64(fields[15])
	stat.Nice = parseInt64(fields[16])
	stat.Threads = parseInt64(fields[17])
	stat.StartTicks = parseUint(fields[19])
	stat.Processor = parseInt64(fields[36])
	stat.Policy = parseInt64(fields[38])

	return stat, nil
}

func buildIdentity(config Config, status StatusData, stat StatData) Identity {
	processRoot := filepath.Join(config.ProcRoot, strconv.Itoa(config.PID))

	uid := parseIDSet(status.Values["Uid"])
	gid := parseIDSet(status.Values["Gid"])

	username := lookupUsername(uid[1])
	groupname := lookupGroup(gid[1])

	executable, _ := os.Readlink(filepath.Join(processRoot, "exe"))
	cwd, _ := os.Readlink(filepath.Join(processRoot, "cwd"))
	root, _ := os.Readlink(filepath.Join(processRoot, "root"))

	command := readCommandLine(filepath.Join(processRoot, "cmdline"))
	if command == "" {
		command = "[" + status.Values["Name"] + "]"
	}

	return Identity{
		PID:          config.PID,
		PPID:         stat.PPID,
		TGID:         parseInt(status.Values["Tgid"]),
		Name:         status.Values["Name"],
		State:        status.Values["State"],
		UIDReal:      uid[0],
		UIDEffective: uid[1],
		UIDSaved:     uid[2],
		UIDFS:        uid[3],
		GIDReal:      gid[0],
		GIDEffective: gid[1],
		GIDSaved:     gid[2],
		GIDFS:        gid[3],
		User:         username,
		Group:        groupname,
		Executable:   executable,
		CWD:          cwd,
		Root:         root,
		Command:      command,
	}
}

func buildCPU(config Config, status StatusData, stat StatData) CPUInfo {
	uptime := readUptime(filepath.Join(config.ProcRoot, "uptime"))
	ticks := clockTicks()

	startSeconds := float64(stat.StartTicks) / float64(ticks)
	elapsed := uptime - startSeconds

	if elapsed < 0 {
		elapsed = 0
	}

	return CPUInfo{
		UserTicks:      stat.UserTicks,
		SystemTicks:    stat.SystemTicks,
		ChildrenUser:   stat.ChildrenUser,
		ChildrenSystem: stat.ChildrenSystem,
		StartTicks:     stat.StartTicks,
		Priority:       stat.Priority,
		Nice:           stat.Nice,
		Processor:      stat.Processor,
		Policy:         stat.Policy,
		Threads:        stat.Threads,
		VoluntaryCS:    parseFirstUint(status.Values["voluntary_ctxt_switches"]),
		InvoluntaryCS:  parseFirstUint(status.Values["nonvoluntary_ctxt_switches"]),
		AllowedCPUs:    status.Values["Cpus_allowed"],
		AllowedCPUList: status.Values["Cpus_allowed_list"],
		ElapsedSeconds: elapsed,
	}
}

func buildMemory(status StatusData) MemoryInfo {
	return MemoryInfo{
		VirtualBytes:      parseKB(status.Values["VmSize"]),
		ResidentBytes:     parseKB(status.Values["VmRSS"]),
		SharedBytes:       parseKB(status.Values["RssFile"]) + parseKB(status.Values["RssShmem"]),
		DataBytes:         parseKB(status.Values["VmData"]),
		StackBytes:        parseKB(status.Values["VmStk"]),
		ExecutableBytes:   parseKB(status.Values["VmExe"]),
		LibraryBytes:      parseKB(status.Values["VmLib"]),
		SwapBytes:         parseKB(status.Values["VmSwap"]),
		PeakVirtualBytes:  parseKB(status.Values["VmPeak"]),
		PeakResidentBytes: parseKB(status.Values["VmHWM"]),
		AnonymousBytes:    parseKB(status.Values["RssAnon"]),
		HugeTLBBytes:      parseKB(status.Values["HugetlbPages"]),
	}
}

func readIO(path string) (IOInfo, error) {
	var info IOInfo

	file, err := os.Open(path)
	if err != nil {
		return info, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		index := strings.IndexByte(line, ':')
		if index < 0 {
			continue
		}

		key := strings.TrimSpace(line[:index])
		value := parseUint(strings.TrimSpace(line[index+1:]))

		switch key {
		case "rchar":
			info.RChar = value
		case "wchar":
			info.WChar = value
		case "syscr":
			info.ReadSyscalls = value
		case "syscw":
			info.WriteSyscalls = value
		case "read_bytes":
			info.ReadBytes = value
		case "write_bytes":
			info.WriteBytes = value
		case "cancelled_write_bytes":
			info.CancelledWrite = value
		}
	}

	return info, scanner.Err()
}

func buildSecurity(processRoot string, status StatusData) SecurityInfo {
	info := SecurityInfo{
		Seccomp:         parseInt(status.Values["Seccomp"]),
		SeccompFilters:  parseInt(status.Values["Seccomp_filters"]),
		NoNewPrivileges: parseInt(status.Values["NoNewPrivs"]) != 0,
		CapInheritable:  status.Values["CapInh"],
		CapPermitted:    status.Values["CapPrm"],
		CapEffective:    status.Values["CapEff"],
		CapBounding:     status.Values["CapBnd"],
		CapAmbient:      status.Values["CapAmb"],
		TracerPID:       parseInt(status.Values["TracerPid"]),
		CoreDumping:     parseInt(status.Values["CoreDumping"]) != 0,
	}

	context := readTrimmed(filepath.Join(processRoot, "attr", "current"))
	info.SELinuxContext = fallback(context, "unavailable")

	for key, value := range status.Values {
		if strings.HasPrefix(key, "Speculation_") {
			info.Speculation = append(info.Speculation, key+": "+value)
		}
	}

	sort.Strings(info.Speculation)

	return info
}

func readNamespaces(path string) ([]NamespaceInfo, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var namespaces []NamespaceInfo

	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(path, entry.Name()))
		if err != nil {
			continue
		}

		namespaces = append(namespaces, NamespaceInfo{
			Name:   entry.Name(),
			Target: target,
			Inode:  parseBracketInode(target),
		})
	}

	sort.Slice(namespaces, func(i, j int) bool {
		return namespaces[i].Name < namespaces[j].Name
	})

	return namespaces, nil
}

func readCgroups(path string) ([]CgroupInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []CgroupInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)

		if len(parts) != 3 {
			continue
		}

		var controllers []string

		if parts[1] != "" {
			controllers = strings.Split(parts[1], ",")
		}

		result = append(result, CgroupInfo{
			HierarchyID: parts[0],
			Controllers: controllers,
			Path:        parts[2],
		})
	}

	return result, scanner.Err()
}

func readFDs(processRoot string, includeEntries bool) (FDSummary, map[uint64]int, error) {
	var summary FDSummary
	socketInodes := make(map[uint64]int)

	path := filepath.Join(processRoot, "fd")
	entries, err := os.ReadDir(path)

	if err != nil {
		return summary, socketInodes, err
	}

	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		target, err := os.Readlink(filepath.Join(path, entry.Name()))
		if err != nil {
			continue
		}

		fdType := classifyFD(target)
		summary.Total++

		switch fdType {
		case "socket":
			summary.Sockets++
			if inode := parseSocketInode(target); inode > 0 {
				socketInodes[inode] = fd
			}
		case "pipe":
			summary.Pipes++
		case "anon_inode":
			summary.AnonInodes++
		case "directory":
			summary.Directories++
		case "file":
			summary.Files++
		default:
			summary.Other++
		}

		if includeEntries {
			summary.Entries = append(summary.Entries, FDInfo{
				FD:     fd,
				Target: target,
				Type:   fdType,
			})
		}
	}

	sort.Slice(summary.Entries, func(i, j int) bool {
		return summary.Entries[i].FD < summary.Entries[j].FD
	})

	return summary, socketInodes, nil
}

func classifyFD(target string) string {
	switch {
	case strings.HasPrefix(target, "socket:["):
		return "socket"
	case strings.HasPrefix(target, "pipe:["):
		return "pipe"
	case strings.HasPrefix(target, "anon_inode:"):
		return "anon_inode"
	}

	info, err := os.Stat(target)
	if err != nil {
		return "other"
	}

	if info.IsDir() {
		return "directory"
	}

	if info.Mode().IsRegular() {
		return "file"
	}

	return "other"
}

func readSockets(processRoot string, wanted map[uint64]int) ([]SocketInfo, error) {
	netRoot := filepath.Join(processRoot, "net")
	records := make(map[uint64]SocketRecord)

	tables := []struct {
		Name     string
		Protocol string
		IPv6     bool
	}{
		{"tcp", "tcp", false},
		{"tcp6", "tcp6", true},
		{"udp", "udp", false},
		{"udp6", "udp6", true},
	}

	var firstErr error

	for _, table := range tables {
		path := filepath.Join(netRoot, table.Name)

		found, err := readInetSocketTable(path, table.Protocol, table.IPv6)
		if err != nil {
			if !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
			continue
		}

		for inode, record := range found {
			records[inode] = record
		}
	}

	if unixRecords, err := readUnixSocketTable(filepath.Join(netRoot, "unix")); err == nil {
		for inode, record := range unixRecords {
			records[inode] = record
		}
	} else if !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}

	var result []SocketInfo

	for inode, fd := range wanted {
		record, ok := records[inode]

		if !ok {
			result = append(result, SocketInfo{
				FD:       fd,
				Inode:    inode,
				Protocol: "unknown",
			})
			continue
		}

		result = append(result, SocketInfo{
			FD:       fd,
			Inode:    inode,
			Protocol: record.Protocol,
			Local:    record.Local,
			Remote:   record.Remote,
			State:    record.State,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].FD < result[j].FD
	})

	return result, firstErr
}

func readInetSocketTable(path, protocol string, ipv6 bool) (map[uint64]SocketRecord, error) {
	result := make(map[uint64]SocketRecord)

	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true

	for scanner.Scan() {
		if first {
			first = false
			continue
		}

		fields := strings.Fields(scanner.Text())

		if len(fields) < 10 {
			continue
		}

		inode := parseUint(fields[9])

		if inode == 0 {
			continue
		}

		result[inode] = SocketRecord{
			Protocol: protocol,
			Local:    decodeEndpoint(fields[1], ipv6),
			Remote:   decodeEndpoint(fields[2], ipv6),
			State:    socketState(fields[3]),
			Inode:    inode,
		}
	}

	return result, scanner.Err()
}

func readUnixSocketTable(path string) (map[uint64]SocketRecord, error) {
	result := make(map[uint64]SocketRecord)

	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true

	for scanner.Scan() {
		if first {
			first = false
			continue
		}

		fields := strings.Fields(scanner.Text())

		if len(fields) < 7 {
			continue
		}

		inode := parseUint(fields[6])

		if inode == 0 {
			continue
		}

		pathName := ""
		if len(fields) >= 8 {
			pathName = strings.Join(fields[7:], " ")
		}

		result[inode] = SocketRecord{
			Protocol: "unix",
			Local:    pathName,
			Inode:    inode,
		}
	}

	return result, scanner.Err()
}

func decodeEndpoint(value string, ipv6 bool) string {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return value
	}

	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return value
	}

	if ipv6 {
		return "[" + decodeIPv6(parts[0]) + "]:" + strconv.FormatUint(port, 10)
	}

	return decodeIPv4(parts[0]) + ":" + strconv.FormatUint(port, 10)
}

func decodeIPv4(value string) string {
	if len(value) != 8 {
		return value
	}

	raw, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return value
	}

	return fmt.Sprintf(
		"%d.%d.%d.%d",
		byte(raw),
		byte(raw>>8),
		byte(raw>>16),
		byte(raw>>24),
	)
}

func decodeIPv6(value string) string {
	if len(value) != 32 {
		return value
	}

	var words []string

	for i := 0; i < 32; i += 8 {
		chunk := value[i : i+8]

		raw, err := strconv.ParseUint(chunk, 16, 32)
		if err != nil {
			return value
		}

		swapped := []byte{
			byte(raw),
			byte(raw >> 8),
			byte(raw >> 16),
			byte(raw >> 24),
		}

		words = append(
			words,
			fmt.Sprintf("%02x%02x:%02x%02x", swapped[0], swapped[1], swapped[2], swapped[3]),
		)
	}

	return strings.Join(words, ":")
}

func socketState(value string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
		"0C": "NEW_SYN_RECV",
	}

	if state, ok := states[strings.ToUpper(value)]; ok {
		return state
	}

	return value
}

func readThreads(processRoot string, include bool) ([]ThreadInfo, error) {
	path := filepath.Join(processRoot, "task")

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	if !include {
		return nil, nil
	}

	var result []ThreadInfo

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		status, err := readStatus(filepath.Join(path, entry.Name(), "status"))
		if err != nil {
			continue
		}

		result = append(result, ThreadInfo{
			TID:   tid,
			Name:  status.Values["Name"],
			State: status.Values["State"],
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TID < result[j].TID
	})

	return result, nil
}

func readMaps(path string, includeFiles bool) (MapSummary, error) {
	var summary MapSummary

	file, err := os.Open(path)
	if err != nil {
		return summary, err
	}
	defer file.Close()

	files := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		if len(fields) < 5 {
			continue
		}

		summary.Regions++

		perms := fields[1]

		if strings.Contains(perms, "x") {
			summary.Executable++
		}

		if strings.Contains(perms, "w") {
			summary.Writable++
		}

		pathname := ""

		if len(fields) >= 6 {
			pathname = strings.Join(fields[5:], " ")
		}

		if pathname == "" || strings.HasPrefix(pathname, "[") {
			summary.Anonymous++
		} else {
			summary.FileBacked++

			if strings.HasSuffix(pathname, " (deleted)") {
				summary.Deleted++
			}

			files[pathname] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return summary, err
	}

	summary.UniqueFiles = len(files)

	if includeFiles {
		for name := range files {
			summary.Files = append(summary.Files, name)
		}
		sort.Strings(summary.Files)
	}

	return summary, nil
}

func readEnvironment(path string, includeValues bool) (EnvironmentInfo, error) {
	var info EnvironmentInfo

	data, err := os.ReadFile(path)
	if err != nil {
		return info, err
	}

	if includeValues {
		info.Variables = make(map[string]string)
	}

	for _, entry := range strings.Split(string(data), "\x00") {
		if entry == "" {
			continue
		}

		info.Count++

		if !includeValues {
			continue
		}

		parts := strings.SplitN(entry, "=", 2)

		if len(parts) == 2 {
			info.Variables[parts[0]] = parts[1]
		} else {
			info.Variables[entry] = ""
		}
	}

	return info, nil
}

func readLimits(path string) (LimitsInfo, error) {
	var info LimitsInfo

	file, err := os.Open(path)
	if err != nil {
		return info, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "Max open files"):
			soft, hard := parseLimitLine(strings.TrimPrefix(line, "Max open files"))
			info.OpenFilesSoft = soft
			info.OpenFilesHard = hard

		case strings.HasPrefix(line, "Max processes"):
			soft, hard := parseLimitLine(strings.TrimPrefix(line, "Max processes"))
			info.ProcessesSoft = soft
			info.ProcessesHard = hard

		case strings.HasPrefix(line, "Max locked memory"):
			soft, hard := parseLimitLine(strings.TrimPrefix(line, "Max locked memory"))
			info.LockedSoft = soft
			info.LockedHard = hard

		case strings.HasPrefix(line, "Max address space"):
			soft, hard := parseLimitLine(strings.TrimPrefix(line, "Max address space"))
			info.AddressSoft = soft
			info.AddressHard = hard
		}
	}

	return info, scanner.Err()
}

func parseLimitLine(value string) (uint64, uint64) {
	fields := strings.Fields(value)

	if len(fields) < 2 {
		return 0, 0
	}

	return parseLimit(fields[0]), parseLimit(fields[1])
}

func parseLimit(value string) uint64 {
	if value == "unlimited" {
		return ^uint64(0)
	}

	return parseUint(value)
}

func readCommandLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	parts := strings.Split(string(data), "\x00")
	var clean []string

	for _, part := range parts {
		if part != "" {
			clean = append(clean, part)
		}
	}

	return strings.Join(clean, " ")
}

func readUptime(path string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}

	value, _ := strconv.ParseFloat(fields[0], 64)
	return value
}

func clockTicks() uint64 {
	return 100
}

func parseIDSet(value string) [4]uint64 {
	var result [4]uint64
	fields := strings.Fields(value)

	for i := 0; i < len(fields) && i < 4; i++ {
		result[i] = parseUint(fields[i])
	}

	return result
}

func lookupUsername(uid uint64) string {
	value := strconv.FormatUint(uid, 10)

	account, err := user.LookupId(value)
	if err != nil {
		return value
	}

	return account.Username
}

func lookupGroup(gid uint64) string {
	value := strconv.FormatUint(gid, 10)

	group, err := user.LookupGroupId(value)
	if err != nil {
		return value
	}

	return group.Name
}

func parseBracketInode(value string) uint64 {
	start := strings.IndexByte(value, '[')
	end := strings.IndexByte(value, ']')

	if start < 0 || end <= start {
		return 0
	}

	return parseUint(value[start+1 : end])
}

func parseSocketInode(value string) uint64 {
	if !strings.HasPrefix(value, "socket:[") {
		return 0
	}

	return parseBracketInode(value)
}

func parseKB(value string) uint64 {
	fields := strings.Fields(value)

	if len(fields) == 0 {
		return 0
	}

	return parseUint(fields[0]) * 1024
}

func parseFirstUint(value string) uint64 {
	fields := strings.Fields(value)

	if len(fields) == 0 {
		return 0
	}

	return parseUint(fields[0])
}

func parseUint(value string) uint64 {
	result, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	return result
}

func parseInt(value string) int {
	result, _ := strconv.Atoi(strings.TrimSpace(value))
	return result
}

func parseInt64(value string) int64 {
	result, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return result
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

func fallback(value, replacement string) string {
	if strings.TrimSpace(value) == "" {
		return replacement
	}

	return value
}

func printJSON(dossier ProcessDossier) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(dossier)
}

func printHuman(d ProcessDossier) {
	fmt.Println("Process Forensics")
	fmt.Println("=================")
	fmt.Println()
	fmt.Printf("Host:          %s\n", d.Hostname)
	fmt.Printf("Kernel:        %s\n", d.Kernel)
	fmt.Printf("Architecture:  %s\n", d.Architecture)
	fmt.Printf("Time:          %s\n", d.Timestamp)

	fmt.Println()
	fmt.Println("Identity")
	fmt.Println("--------")
	fmt.Printf("PID:           %d\n", d.Identity.PID)
	fmt.Printf("PPID:          %d\n", d.Identity.PPID)
	fmt.Printf("TGID:          %d\n", d.Identity.TGID)
	fmt.Printf("Name:          %s\n", d.Identity.Name)
	fmt.Printf("State:         %s\n", d.Identity.State)
	fmt.Printf("User:          %s (%d)\n", d.Identity.User, d.Identity.UIDEffective)
	fmt.Printf("Group:         %s (%d)\n", d.Identity.Group, d.Identity.GIDEffective)
	fmt.Printf("Executable:    %s\n", fallback(d.Identity.Executable, "unavailable"))
	fmt.Printf("CWD:           %s\n", fallback(d.Identity.CWD, "unavailable"))
	fmt.Printf("Root:          %s\n", fallback(d.Identity.Root, "unavailable"))
	fmt.Printf("Command:       %s\n", d.Identity.Command)

	fmt.Println()
	fmt.Println("CPU and Scheduling")
	fmt.Println("------------------")
	fmt.Printf("Threads:       %d\n", d.CPU.Threads)
	fmt.Printf("Processor:     %d\n", d.CPU.Processor)
	fmt.Printf("Priority:      %d\n", d.CPU.Priority)
	fmt.Printf("Nice:          %d\n", d.CPU.Nice)
	fmt.Printf("Policy:        %d\n", d.CPU.Policy)
	fmt.Printf("User ticks:    %d\n", d.CPU.UserTicks)
	fmt.Printf("System ticks:  %d\n", d.CPU.SystemTicks)
	fmt.Printf("Elapsed:       %s\n", formatDuration(d.CPU.ElapsedSeconds))
	fmt.Printf("CPU allowed:   %s\n", fallback(d.CPU.AllowedCPUList, "unknown"))
	fmt.Printf("Context sw:    %d voluntary, %d involuntary\n", d.CPU.VoluntaryCS, d.CPU.InvoluntaryCS)

	fmt.Println()
	fmt.Println("Memory")
	fmt.Println("------")
	fmt.Printf("Virtual:       %s\n", formatBytes(d.Memory.VirtualBytes))
	fmt.Printf("Resident:      %s\n", formatBytes(d.Memory.ResidentBytes))
	fmt.Printf("Anonymous:     %s\n", formatBytes(d.Memory.AnonymousBytes))
	fmt.Printf("Shared:        %s\n", formatBytes(d.Memory.SharedBytes))
	fmt.Printf("Data:          %s\n", formatBytes(d.Memory.DataBytes))
	fmt.Printf("Stack:         %s\n", formatBytes(d.Memory.StackBytes))
	fmt.Printf("Executable:    %s\n", formatBytes(d.Memory.ExecutableBytes))
	fmt.Printf("Libraries:     %s\n", formatBytes(d.Memory.LibraryBytes))
	fmt.Printf("Swap:          %s\n", formatBytes(d.Memory.SwapBytes))
	fmt.Printf("Peak RSS:      %s\n", formatBytes(d.Memory.PeakResidentBytes))
	fmt.Printf("Peak virtual:  %s\n", formatBytes(d.Memory.PeakVirtualBytes))

	fmt.Println()
	fmt.Println("I/O")
	fmt.Println("---")
	fmt.Printf("Read bytes:    %s\n", formatBytes(d.IO.ReadBytes))
	fmt.Printf("Write bytes:   %s\n", formatBytes(d.IO.WriteBytes))
	fmt.Printf("Read calls:    %d\n", d.IO.ReadSyscalls)
	fmt.Printf("Write calls:   %d\n", d.IO.WriteSyscalls)
	fmt.Printf("RChar:         %s\n", formatBytes(d.IO.RChar))
	fmt.Printf("WChar:         %s\n", formatBytes(d.IO.WChar))
	fmt.Printf("Cancelled:     %s\n", formatBytes(d.IO.CancelledWrite))

	fmt.Println()
	fmt.Println("Security")
	fmt.Println("--------")
	fmt.Printf("SELinux:       %s\n", d.Security.SELinuxContext)
	fmt.Printf("Seccomp:       %s\n", seccompName(d.Security.Seccomp))
	fmt.Printf("Filters:       %d\n", d.Security.SeccompFilters)
	fmt.Printf("NoNewPrivs:    %t\n", d.Security.NoNewPrivileges)
	fmt.Printf("Tracer PID:    %d\n", d.Security.TracerPID)
	fmt.Printf("Core dumping:  %t\n", d.Security.CoreDumping)
	fmt.Printf("Cap effective: %s\n", fallback(d.Security.CapEffective, "unavailable"))
	fmt.Printf("Cap permitted: %s\n", fallback(d.Security.CapPermitted, "unavailable"))
	fmt.Printf("Cap bounding:  %s\n", fallback(d.Security.CapBounding, "unavailable"))
	fmt.Printf("Cap ambient:   %s\n", fallback(d.Security.CapAmbient, "unavailable"))

	if len(d.Security.Speculation) > 0 {
		fmt.Println()
		fmt.Println("Speculation Controls")
		fmt.Println("--------------------")
		for _, item := range d.Security.Speculation {
			fmt.Println(item)
		}
	}

	fmt.Println()
	fmt.Println("Namespaces")
	fmt.Println("----------")

	if len(d.Namespaces) == 0 {
		fmt.Println("Unavailable")
	} else {
		for _, namespace := range d.Namespaces {
			fmt.Printf("%-10s %-20s inode %d\n", namespace.Name, namespace.Target, namespace.Inode)
		}
	}

	fmt.Println()
	fmt.Println("Cgroups")
	fmt.Println("-------")

	if len(d.Cgroups) == 0 {
		fmt.Println("Unavailable")
	} else {
		for _, group := range d.Cgroups {
			controllers := strings.Join(group.Controllers, ",")
			if controllers == "" {
				controllers = "unified"
			}

			fmt.Printf("%s  %s  %s\n", group.HierarchyID, controllers, group.Path)
		}
	}

	fmt.Println()
	fmt.Println("File Descriptors")
	fmt.Println("----------------")
	fmt.Printf("Total:         %d\n", d.FDs.Total)
	fmt.Printf("Files:         %d\n", d.FDs.Files)
	fmt.Printf("Directories:   %d\n", d.FDs.Directories)
	fmt.Printf("Sockets:       %d\n", d.FDs.Sockets)
	fmt.Printf("Pipes:         %d\n", d.FDs.Pipes)
	fmt.Printf("Anon inodes:   %d\n", d.FDs.AnonInodes)
	fmt.Printf("Other:         %d\n", d.FDs.Other)
	fmt.Printf("Open limit:    %s / %s\n", formatLimit(d.FDs.LimitSoft), formatLimit(d.FDs.LimitHard))

	if len(d.FDs.Entries) > 0 {
		fmt.Println()
		fmt.Println("FD Table")
		fmt.Println("--------")
		for _, fd := range d.FDs.Entries {
			fmt.Printf("%-6d %-12s %s\n", fd.FD, fd.Type, fd.Target)
		}
	}

	if len(d.Sockets) > 0 {
		fmt.Println()
		fmt.Println("Sockets")
		fmt.Println("-------")

		for _, socket := range d.Sockets {
			fmt.Printf("FD %-5d %-7s inode %-12d", socket.FD, socket.Protocol, socket.Inode)

			if socket.Local != "" {
				fmt.Printf(" local=%s", socket.Local)
			}

			if socket.Remote != "" {
				fmt.Printf(" remote=%s", socket.Remote)
			}

			if socket.State != "" {
				fmt.Printf(" state=%s", socket.State)
			}

			fmt.Println()
		}
	}

	fmt.Println()
	fmt.Println("Memory Maps")
	fmt.Println("-----------")
	fmt.Printf("Regions:       %d\n", d.Maps.Regions)
	fmt.Printf("Executable:    %d\n", d.Maps.Executable)
	fmt.Printf("Writable:      %d\n", d.Maps.Writable)
	fmt.Printf("Anonymous:     %d\n", d.Maps.Anonymous)
	fmt.Printf("File backed:   %d\n", d.Maps.FileBacked)
	fmt.Printf("Deleted:       %d\n", d.Maps.Deleted)
	fmt.Printf("Unique files:  %d\n", d.Maps.UniqueFiles)

	if len(d.Maps.Files) > 0 {
		fmt.Println()
		fmt.Println("Mapped Files")
		fmt.Println("------------")
		for _, name := range d.Maps.Files {
			fmt.Println(name)
		}
	}

	fmt.Println()
	fmt.Println("Environment")
	fmt.Println("-----------")
	fmt.Printf("Variables:     %d\n", d.Environment.Count)

	if len(d.Environment.Variables) > 0 {
		keys := make([]string, 0, len(d.Environment.Variables))

		for key := range d.Environment.Variables {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		for _, key := range keys {
			fmt.Printf("%s=%s\n", key, d.Environment.Variables[key])
		}
	}

	if len(d.Threads) > 0 {
		fmt.Println()
		fmt.Println("Threads")
		fmt.Println("-------")

		for _, thread := range d.Threads {
			fmt.Printf("%-8d %-24s %s\n", thread.TID, thread.Name, thread.State)
		}
	}

	fmt.Println()
	fmt.Println("Resource Limits")
	fmt.Println("---------------")
	fmt.Printf("Open files:    %s / %s\n", formatLimit(d.Limits.OpenFilesSoft), formatLimit(d.Limits.OpenFilesHard))
	fmt.Printf("Processes:     %s / %s\n", formatLimit(d.Limits.ProcessesSoft), formatLimit(d.Limits.ProcessesHard))
	fmt.Printf("Locked memory: %s / %s\n", formatLimit(d.Limits.LockedSoft), formatLimit(d.Limits.LockedHard))
	fmt.Printf("Address space: %s / %s\n", formatLimit(d.Limits.AddressSoft), formatLimit(d.Limits.AddressHard))

	if len(d.Warnings) > 0 {
		fmt.Println()
		fmt.Println("Warnings")
		fmt.Println("--------")

		for _, warning := range d.Warnings {
			fmt.Println(warning)
		}
	}
}

func seccompName(mode int) string {
	switch mode {
	case 0:
		return "disabled"
	case 1:
		return "strict"
	case 2:
		return "filter"
	default:
		return fmt.Sprintf("unknown (%d)", mode)
	}
}

func formatBytes(value uint64) string {
	const (
		kib = uint64(1024)
		mib = kib * 1024
		gib = mib * 1024
		tib = gib * 1024
	)

	switch {
	case value >= tib:
		return fmt.Sprintf("%.2f TiB", float64(value)/float64(tib))
	case value >= gib:
		return fmt.Sprintf("%.2f GiB", float64(value)/float64(gib))
	case value >= mib:
		return fmt.Sprintf("%.2f MiB", float64(value)/float64(mib))
	case value >= kib:
		return fmt.Sprintf("%.2f KiB", float64(value)/float64(kib))
	default:
		return fmt.Sprintf("%d B", value)
	}
}

func formatDuration(seconds float64) string {
	if seconds < 0 {
		seconds = 0
	}

	duration := uint64(seconds)
	days := duration / 86400
	duration %= 86400
	hours := duration / 3600
	duration %= 3600
	minutes := duration / 60
	secs := duration % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, secs)
	case hours > 0:
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, secs)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, secs)
	default:
		return fmt.Sprintf("%ds", secs)
	}
}

func formatLimit(value uint64) string {
	if value == ^uint64(0) {
		return "unlimited"
	}

	return strconv.FormatUint(value, 10)
}
