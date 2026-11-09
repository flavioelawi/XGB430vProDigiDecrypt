package digicredentials

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func prompt(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	v, err := reader.ReadString('\n')
	if err != nil && len(v) == 0 {
		return "", err
	}
	return strings.TrimSpace(v), nil
}

func passwordPrompt() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fail("No secure terminal is available for password entry. Open an interactive console.")
	}
	fmt.Print("Password: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fail("Unable to read the password securely.")
	}
	return string(b), nil
}

// Run executes the interactive credential reader and returns a process exit code.
func Run() int {
	if len(os.Args) == 2 && os.Args[1] == "--debug" {
		debugEnabled = true
	} else if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "Error: only --debug is supported.")
		return 1
	}
	debugf("debug logging enabled; sensitive values are redacted")
	fmt.Println("TP-Link XGB430v Pro ESDIGI — local read; no files are saved.")
	reader := bufio.NewReader(os.Stdin)
	address, err := prompt(reader, "Router IP: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nCancelled.")
		return 130
	}
	h, err := newRouterHTTP(address)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nError:", err)
		return 1
	}
	c := newRouterClient(h)
	fmt.Println("Checking the router login protocol...")
	if err = c.prepare(); err != nil {
		fmt.Fprintln(os.Stderr, "\nError:", err)
		return 1
	}
	user, err := prompt(reader, "Username: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nCancelled.")
		return 130
	}
	password, err := passwordPrompt()
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nError:", err)
		return 1
	}
	fmt.Println("Logging in...")
	defer c.logout()
	if err = c.login(user, password); err != nil {
		fmt.Fprintln(os.Stderr, "\nError:", err)
		return 1
	}
	password = ""
	fmt.Println("Downloading and verifying the backup in memory...")
	backup, err := c.downloadBackup()
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nError:", err)
		return 1
	}
	config, err := decryptBackup(backup)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nError:", err)
		return 1
	}
	root, err := parseConfig(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nError:", err)
		return 1
	}
	g := credentialGroups(root)
	for i, x := range []struct {
		label, kind string
		records     []record
	}{{"Admin", "admin", g.admin}, {"PPPoE", "ppp", g.ppp}, {"SIP", "sip", g.sip}} {
		if i > 0 {
			fmt.Println()
		}
		u, p := summary(x.records, x.kind)
		fmt.Printf("%s user: %s\n%s password: %s\n", x.label, display(u), x.label, display(p))
	}
	return 0
}
