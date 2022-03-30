package main

import (
    "github.com/keys-pub/go-libfido2"
    "github.com/odatam/base58"    
	"encoding/hex"
	"log"
	"encoding/json"
	"io/ioutil"
	"os"
	"crypto/rand"
	"crypto/sha256"	
	"bytes"
	"encoding/base64"
	"flag"
	"golang.org/x/term"
	"fmt"
	"strings"
	"path/filepath"
	"os/exec"
	"errors"
)

type GoFido2PassItem struct { 
	UserId string
	UserName string
	AuthData string
	ClientDataHash string
	CredentialId string
	CredentialType string
	CredentialCert string
	CredentialPubKey string
	CredentialSignature string
	CredentialFormat string
	Salt string
	Length int
}

type GoFido2PassItems []GoFido2PassItem

type GoFido2PassConfig struct {
	Version string
	Credentials GoFido2PassItems
}

func createCred(device *libfido2.Device, relyingParty string, userId []byte, userName string, cdh []byte, pin string) (*libfido2.Attestation, error)  {
    attest, err := device.MakeCredential(
        cdh,
        libfido2.RelyingParty{
            ID: relyingParty,
        },
        libfido2.User{
            ID:   userId,
            Name: userName,
        },
        libfido2.ES256, // Algorithm
        pin,
        &libfido2.MakeCredentialOpts{
            Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
            UV:         libfido2.False,
        },
    )
    if err != nil {
        log.Fatal(err)
    }

	return attest, nil
}

func getAssertion(device *libfido2.Device, rpId string, credId []byte, cdh []byte, pin string, salt []byte) (*libfido2.Assertion, error) {
   assertion, err := device.Assertion(
        rpId,
        cdh,
        [][]byte{credId},
        pin,
        &libfido2.AssertionOpts{
            Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
            HMACSalt:   salt,
            UP:         libfido2.False,
        },
    )
    if err != nil {
    	return nil, err
    }

	return assertion, nil
}

const (
	GOFIDO2PASS_RPID = "GoFido2Pass"
	GOFIDO2PASS_CONFIG_DIR = "gofido2pass"
	GOFIDO2PASS_CONFIG_FILE = "gofido2pass.json"
	GOFIDO2PASS_VERSION = "1.0"
	GOFIDO2PASS_SALT_LENGTH = 64
	GOFIDO2PASS_USERNAME_DEFAULT_PREFIX = "gofido2pass-u-"
	GOFIDO2PASS_DEBUG = false
)

func readPIN() (string, error) {
    fmt.Fprintln(os.Stdout, "Enter PIN: ")
    bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
    if err != nil {
        return "", err
    }

    password := string(bytePassword)
    return password, nil
}

const fd0 = "/proc/self/fd/0"

// TTY prints the file name of the terminal connected to standard input
func TTY() (string, error) {
	dest, err := os.Readlink(fd0)
	if err != nil {
		return "", err
	}
	return dest, nil
}

func readPINFromTTY() (string, error) {
	ttyname, err := TTY()
	if err != nil {
		return "", err
	}
	tty, err := os.Open(ttyname)
    if err != nil {
		return "", err
    }
    defer tty.Close()
    fd := int(tty.Fd())
 
    fmt.Fprintln(os.Stderr, "(from "+ttyname+") Enter FIDO2 KEY PIN: ")
    pass, err := term.ReadPassword(fd)
    
    return string(pass), err
}

func CmdZenityPass() (string, error) {
	cmd := exec.Command("zenity", "--entry", "--title=PIN", "--text=Enter FIDO2 KEY PIN", "--hide-text")	
	outlog, _ := cmd.CombinedOutput()
	out := string(outlog)
	if ((cmd.ProcessState.ExitCode() == 0)) {
		out = strings.TrimSpace(out)
		return out, nil
	}

	return "", errors.New("zenity pin Failed")
}

func printDebug(format string, a ...interface{}) () {
	if (GOFIDO2PASS_DEBUG) {
		if (len(a) == 0) {
			fmt.Fprintln(os.Stderr, format)
		} else {
			fmt.Fprintf(os.Stderr, format, a)
		}
	}
}

func main() {
	var gofido2passconfig GoFido2PassConfig
	var gofido2passitem GoFido2PassItem

	var createBool bool
	var listBool bool
	var forceBool bool	
	var ttyBool bool	
	var hexBool bool
	var base58Bool bool	
	var lengthParam int
						
	homeDir, err := os.UserHomeDir()
    if err != nil {
        log.Fatalln( err )
    }
    configDir := filepath.Join(homeDir, ".config", GOFIDO2PASS_CONFIG_DIR)
    _, err = os.Stat(configDir)
    if os.IsNotExist(err) {
        fmt.Fprintln(os.Stderr, "Creating config dir...")
        err = os.Mkdir(configDir, 0700)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR creating config dir !")
			os.Exit(1)
		}
    }
    
    configFile := filepath.Join(configDir, GOFIDO2PASS_CONFIG_FILE)
    
	userNameParam := ""
	gofido2passitem = GoFido2PassItem{}
	
	flag.StringVar(&userNameParam, "u", "default", "Specify username")
    flag.BoolVar(&createBool, "c", false, "Create credential")
    flag.BoolVar(&listBool, "l", false, "List credentials")
	flag.IntVar(&lengthParam, "s", 0, "Passphrase length (default 0 : unlimited)")
	flag.BoolVar(&forceBool, "f", false, "Force length")
	flag.BoolVar(&ttyBool, "tty", false, "TTY pin entry")	
    flag.BoolVar(&hexBool, "hex", false, "hex output")	
    flag.BoolVar(&base58Bool, "base58", true, "base58 output")	
    
    flag.Usage = func() {
    	fmt.Fprintln(os.Stderr, "Usage :")
        fmt.Fprintln(os.Stderr, "./gofido2pass -u CLEFID1234 [-c [-s len]] [-l] [-f] [-hex] [-base58]")
        os.Exit(1)
    }

    flag.Parse()

	if ((flag.NFlag() < 1) || ((userNameParam == "") && !listBool)) {
    	fmt.Fprintln(os.Stderr, "Too few arguments")
    	flag.Usage()
		os.Exit(1)
	}

    _, err = os.Stat(configFile)
    if os.IsNotExist(err) {
    	gofido2passconfig.Version = GOFIDO2PASS_VERSION
    } else {
		file, _ := ioutil.ReadFile(configFile)
		json.Unmarshal(file, &gofido2passconfig)
		if (len(gofido2passconfig.Version) == 0) {
			gofido2passconfig.Version = GOFIDO2PASS_VERSION
		}
    }

	if (listBool) {
		for _, credential := range gofido2passconfig.Credentials {
			userName := strings.ReplaceAll(credential.UserName, GOFIDO2PASS_USERNAME_DEFAULT_PREFIX, "")
			fmt.Println(userName)
		}
		os.Exit(0)
	}
			
	pin := ""		
    if (ttyBool) {
		pin, err = readPINFromTTY()
	} else {
		pin, err = CmdZenityPass()
	}
	
	if (err != nil) {
		fmt.Fprintln(os.Stderr, "ERROR reading PIN !")
		os.Exit(1)
	}	
	
	if (pin == "") {
		os.Exit(0)
	}

	cdh := libfido2.RandBytes(32)

    userId := libfido2.RandBytes(32)
	userName := GOFIDO2PASS_USERNAME_DEFAULT_PREFIX+userNameParam

	for _, credential := range gofido2passconfig.Credentials {
		if (credential.UserName == userName) {
			printDebug(credential.UserName)
			printDebug(credential.CredentialId)
			printDebug(credential.Salt)
			gofido2passitem = credential
		}
	}

	if (!createBool && (len(gofido2passitem.CredentialId) == 0)) {
		fmt.Fprintln(os.Stderr, "Credential not found")	
		os.Exit(1)
	}
	
    locs, err := libfido2.DeviceLocations()
    if err != nil {
        fmt.Fprintln(os.Stderr, err.Error())
        os.Exit(1)
    }
    if len(locs) == 0 {
        fmt.Fprintln(os.Stderr, "No devices")
		os.Exit(1)
    }

    printDebug("Using device: %+v\n", locs[0])
    path := locs[0].Path
    device, err := libfido2.NewDevice(path)
    if err != nil {
        fmt.Fprintln(os.Stderr, err.Error())
        os.Exit(1)
    }    
		
	if (createBool) {
	    printDebug("cdh : %s\n", base64.StdEncoding.EncodeToString(cdh))
	    printDebug("userID : %s\n", base64.StdEncoding.EncodeToString(userId))
	    printDebug("userName : %s\n", userName)

		attest, err := createCred(device, GOFIDO2PASS_RPID, userId, userName, cdh, pin)

		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	    printDebug("Attestation:")
	    printDebug("AuthData: %s\n", base64.StdEncoding.EncodeToString(attest.AuthData))
	    printDebug("ClientDataHash: %s\n", base64.StdEncoding.EncodeToString(attest.ClientDataHash))
	    printDebug("ID: %s\n", base64.StdEncoding.EncodeToString(attest.CredentialID))
	    printDebug("Type: %s\n", attest.CredentialType.String())
	    printDebug("Cert: %s\n", base64.StdEncoding.EncodeToString(attest.Cert))
	    printDebug("PubKey: %s\n", base64.StdEncoding.EncodeToString(attest.PubKey))
	    printDebug("Sig: %s\n", base64.StdEncoding.EncodeToString(attest.Sig))
	    printDebug("Format: %s\n", attest.Format) 	

		saltBytes := make([]byte, GOFIDO2PASS_SALT_LENGTH)
		_, err = rand.Read(saltBytes)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Unable to create salt")
			os.Exit(1)
		}
	    
	    goFido2PassItem := GoFido2PassItem{	UserId: base64.StdEncoding.EncodeToString(userId),
			UserName: userName,
			AuthData: base64.StdEncoding.EncodeToString(attest.AuthData),
			ClientDataHash: base64.StdEncoding.EncodeToString(cdh),
			CredentialId: base64.StdEncoding.EncodeToString(attest.CredentialID),
			CredentialType: attest.CredentialType.String(),
			CredentialCert: base64.StdEncoding.EncodeToString(attest.Cert),
			CredentialPubKey: base64.StdEncoding.EncodeToString(attest.PubKey),
			CredentialSignature: base64.StdEncoding.EncodeToString(attest.Sig),
			CredentialFormat: attest.Format,
			Salt: base64.StdEncoding.EncodeToString(saltBytes),
			Length: lengthParam,					
		}
		gofido2passconfig.Credentials = append(gofido2passconfig.Credentials, goFido2PassItem)
		jsonData, _ := json.Marshal(gofido2passconfig)
		printDebug("%s\n", jsonData)				
		ioutil.WriteFile(configFile, jsonData, os.ModePerm)
	}
	
	if (!createBool) {
		cdh = libfido2.RandBytes(32)

		credId, err := base64.StdEncoding.DecodeString(gofido2passitem.CredentialId)
		if (err != nil) {
			fmt.Fprintln(os.Stderr, "Error decoding string: " + err.Error())
			os.Exit(1)
		}
		salt, err := base64.StdEncoding.DecodeString(gofido2passitem.Salt)
		if (err != nil) {
			fmt.Fprintln(os.Stderr, "Error decoding string: " + err.Error())
			os.Exit(1)
		}
		printDebug("cred : %s\n", hex.EncodeToString(credId))		
		printDebug("salt : %s\n", hex.EncodeToString(salt))

		assertion, err := getAssertion(device, GOFIDO2PASS_RPID, credId, cdh, pin, salt)
		if err == nil {
			printDebug("Assertion:")
			printDebug("HMAC : %s\n", hex.EncodeToString(assertion.HMACSecret))
			printDebug("SIG : %s\n", hex.EncodeToString(assertion.Sig))
			var toHashB bytes.Buffer
			toHashB.Write(credId)
			toHashB.Write(salt)
			toHashB.Write(assertion.HMACSecret)
			hash := sha256.Sum256(toHashB.Bytes())
			sliceHash := hash[:]
			hashOutput := ""
			if (hexBool) {
				hashOutput = hex.EncodeToString(sliceHash)
			} else {
				hashOutput, err = base58.Base58EncodeToString(sliceHash)
				if err != nil {
					log.Fatal(err)
				}			
			}
			if (forceBool && (lengthParam >= 0)) {
				if (lengthParam > len(hashOutput)) {
					lengthParam = len(hashOutput)
				}
				gofido2passitem.Length = lengthParam
			}
			if (gofido2passitem.Length > 0) {
				fmt.Printf("%s\n", hashOutput[:gofido2passitem.Length])
			} else {
				fmt.Printf("%s\n", hashOutput)				
			}
		} else {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}	
	}
}
