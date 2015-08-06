// remoteExecutor.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"syscall"
)

const testMessage string = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"

type configFile struct {
	Port           string
	Https_keyfile  string
	Https_certfile string
	App_pub_key    string
	Log_dir        string
}

// Function read configuration and set returm configFile type
func readConfig(confFilePath string) (configFile, error) {
	var config configFile

	confFile, err := ioutil.ReadFile(confFilePath)
	if err != nil {
		return config, err

	}

	json.Unmarshal(confFile, &config)
	return config, nil
}

// Function read public key and represents it as rsa.PublicKey type
func readPublicKey(path string) (*rsa.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	pubkeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	pubkey, ok := pubkeyInterface.(*rsa.PublicKey)
	if !ok {
		log.Println("Error on public key load")
	}
	return pubkey, nil
}

// Function check if private key could decode what public key encode
func authorize(pubkey *rsa.PublicKey, privkey_str []byte) (bool, error) {
	block, _ := pem.Decode(privkey_str)
	if block == nil {
		return false, errors.New("Provided data is not private key")
	}
	if len(block.Bytes) < 100 {
		return false, errors.New("Provided data is not private key")
	}

	privkey := new(rsa.PrivateKey)

	if block.Type == "RSA PRIVATE KEY" {

		privkey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	} else {
		return false, errors.New("Provided data is not private key")
	}

	// Encrypt message
	eComm, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubkey, []byte(testMessage), nil)
	if err != nil {
		return false, err
	}

	log.Println("Encrypted data " + string(eComm[:]))
	log.Println(eComm[:])
	test := []byte{
		75, 171, 179, 168, 150, 13, 169, 80, 26, 131, 139, 152, 174, 42, 69, 237, 56, 148, 43, 29, 48, 179, 116, 109, 226, 86, 102, 236, 225, 150, 192, 52, 96, 6, 203, 147, 106, 50, 228, 117, 89, 220, 214, 2, 156, 53, 86, 236, 73, 167, 186, 30, 27, 140, 67, 181, 65, 176, 95, 115, 189, 99, 72, 219, 88, 158, 242, 101, 78, 244, 137, 80, 150, 26, 20, 163, 190, 26, 165, 45, 82, 228, 140, 100, 116, 210, 63, 247, 103, 14, 131, 22, 172, 128, 171, 121, 13, 218, 2, 217, 119, 51, 243, 39, 22, 49, 165, 4, 204, 248, 251, 129, 190, 153, 27, 170, 56, 83, 108, 87, 56, 187, 88, 9, 119, 35, 247, 125,
	}

	msg1, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privkey, test, nil)

	log.Println(string(msg1))

	// Decrypt message
	msg, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privkey, eComm, nil)
	if err != nil {
		return false, err
	}

	// If Decrypted message euqal with original - private key is correct and user authorized

	if string(msg) == testMessage {
		return true, nil
	}

	return false, nil
}

// function handle execution of command and write output to log and to io.Writer
func runExec(command *exec.Cmd, dir string, logPath string, name string, output io.Writer) error {

	command.Dir = dir

	logFile, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Couldn't open " + name + " log file!")
	}
	defer logFile.Close()

	log.SetOutput(logFile)

	log.Print("Starting " + name + "... ")

	multiOutput := io.MultiWriter(logFile, output)
	command.Stdout = multiOutput
	command.Stderr = multiOutput

	err = command.Start()
	if err != nil {
		log.Println("Error while starting "+name+": ", err)
	}

	log.Print(name + " started")

	err = command.Wait()
	if err != nil {

		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				log.Printf(name+" finished working  with exit Status: %d", status.ExitStatus())
			}
		} else {
			log.Fatalf("cmd.Wait: %v", err)
		}
	}
	return nil
}

// Function handle functionality around firstcommand with parameter from GET request
func firstComand(w http.ResponseWriter, req *http.Request, pubkey *rsa.PublicKey, logDir string, globalLogFile *os.File) {
	w.Header().Set("Content-Type", "text/plain")

	log.SetOutput(globalLogFile)

	// read request body bytes
	body, _ := ioutil.ReadAll(req.Body)

	// Check if sent bytes was a private key if that key is correct
	authorized, err := authorize(pubkey, body)
	if err != nil {
		log.Println("Authorization error ", err)
	}

	if authorized {
		log.Println("Authorized from ", req.RemoteAddr)
		w.Write([]byte("Authorization correct\n"))
	} else {
		log.Println("Failed authorization from", req.RemoteAddr)
		w.Write([]byte("Authorization failed\n"))
		return
	}

	req.ParseForm()

	first := exec.Command("/bin/bash", "-c", "/usr/bin/sudo -u user /path/to_my_bin/first.sh "+req.Form.Get("param"))
	w.Write([]byte("Starting first.sh... "))
	err = runExec(first, "/", logDir+"/first.log", "first", w)
	if err != nil {
		w.Write([]byte("Something went wrong. Check application log for details\n"))
		log.Fatal("Error on first execution ", err)
	}

	w.Write([]byte("OK\nOutput also added to " + logDir + "/fisrt.log" + "\n"))

}

// Function handle functionality around second
func secondCommand(w http.ResponseWriter, req *http.Request, pubkey *rsa.PublicKey, logDir string, globalLogFile *os.File) {
	logFile := logDir + "/second.log"
	log.SetOutput(globalLogFile)

	w.Header().Set("Content-Type", "text/plain")

	// read request body bytes
	body, _ := ioutil.ReadAll(req.Body)

	// Check if sent bytes was a private key if that key is correct
	authorized, err := authorize(pubkey, body)
	if err != nil {
		log.Println("Authorization error ", err)
	}

	w.Write([]byte("Authorization... "))

	if authorized {
		log.Println("Authorized from ", req.RemoteAddr)
		w.Write([]byte("correct\n"))
	} else {
		log.Println("Failed authorization from", req.RemoteAddr)
		w.Write([]byte("failed\n"))
		return
	}

	//check id flag, without it second couldn't be started
	req.ParseForm()
	if req.Form.Get("id") == "" {
		w.Write([]byte("You shoul pass ?id= param, otherwise this will not work\n"))
		log.Println("Request to second without ID")
		return
	}

	second := exec.Command("/path/to/second", req.Form.Get("id"))
	w.Write([]byte("Starting second... "))
	err = runExec(second, "/work_dir", logFile, "second", w)
	if err != nil {
		w.Write([]byte("Something went wrong. Check application log for details\n"))
		log.Fatal("Error on second execution ", err)
	}

	w.Write([]byte("OK\nOutput also added to " + logFile + "\n"))

}

// Function handle functionality around third command
func thirdCommand(w http.ResponseWriter, req *http.Request, pubkey *rsa.PublicKey, logDir string, globalLogFile *os.File) {
	logFile := logDir + "/third.log"
	log.SetOutput(globalLogFile)

	w.Header().Set("Content-Type", "text/plain")

	// read request body bytes
	body, _ := ioutil.ReadAll(req.Body)

	// Check if sent bytes was a private key if that key is correct
	authorized, err := authorize(pubkey, body)
	if err != nil {
		log.Println("Authorization error ", err)
	}

	w.Write([]byte("Authorization... "))

	if authorized {
		log.Println("Authorized from ", req.RemoteAddr)
		w.Write([]byte("correct\n"))
	} else {
		log.Println("Failed authorization from", req.RemoteAddr)
		w.Write([]byte("failed\n"))
		return
	}

	runpl := exec.Command("/bin/bash", "-c", "/usr/bin/sudo /path/to/third")
	w.Write([]byte("Starting third... "))
	err = runExec(runpl, "/home", logFile, "third", w)
	if err != nil {
		w.Write([]byte("Something went wrong. Check application log for details\n"))
		log.Fatal("Error on third execution ", err)
	}

	w.Write([]byte("OK\nOutput also added to " + logFile + "\n"))

}

func main() {

	confFilePath := flag.String("conf", "/home/smishin/go/src/remoteExecutor/config.json", "path to application config")
	flag.Parse()

	config, err := readConfig(*confFilePath)
	if err != nil {
		log.Fatal("Couldn't read config file ", err)
	}

	logFile, err := os.OpenFile(config.Log_dir+"/remoteExecutor.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Couldn't open application log file!")
	}
	defer logFile.Close()

	log.SetOutput(logFile)

	pubkey, err := readPublicKey(config.App_pub_key)
	if err != nil {
		log.Fatal("Error on open public key: ", err)
	}

	// If someone ask root, reply 404
	http.HandleFunc("/", http.NotFound)

	// Handle requests to firstCommand
	http.HandleFunc("/first/", func(w http.ResponseWriter, r *http.Request) {
		firstComand(w, r, pubkey, config.Log_dir, logFile)
	})

	// Handle request to second exec
	http.HandleFunc("/second/", func(w http.ResponseWriter, r *http.Request) {
		secondCommand(w, r, pubkey, config.Log_dir, logFile)
	})

	// Handle request to runpl exec
	http.HandleFunc("/third/", func(w http.ResponseWriter, r *http.Request) {
		thirdCommand(w, r, pubkey, config.Log_dir, logFile)
	})

	err = http.ListenAndServeTLS(":"+config.Port, config.Https_certfile, config.Https_keyfile, nil)

	if err != nil {
		log.Fatal("Error on creating listener: ", err)
	}

	log.Println("remoteExecutor closed.")

}
