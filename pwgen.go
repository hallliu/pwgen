package main

import (
    "fmt"
    "flag"
    "os"
    "crypto/sha512"
    "encoding/hex"
    "errors"
    "bufio"
    "strings"
    "code.google.com/p/gopass"
)

type pwList map[string]*pwInfo 

struct pwInfo {
    alpLength string
    alphabet string
}

func main() {
    setPw := flag.Bool("s", false, "Set/reset master password")
    defaultPath := os.Getenv("HOME") + "/.pwdb"
    pwFileName := flag.String("f", defaultPath, "Password database file, default ~/.pwdb")

    if setPw {
        newMasterPw()
        return
    }


}

func getPwDb(pwFileName string) (pwList, string, error) {
    if _, err := os.Stat(pwFileName); os.IsNotExist(err) {
        pws, mpw, err := newMasterPw(pwFileName)
        if err != nil {
            return nil, nil, err
        }
        return pws, mpw, nil
    }

    pwFile, err := os.Open(pwFileName)
    if err != nil {
        return nil, errors.New(fmt.Sprintf("Error opening %s\n", pwFileName))
    }
    defer pwFile.Close()

    pws := make(map[string]*pwInfo)

    scan := bufio.NewScanner(pwFile)
    scan.Scan()

    masterPwHash := scan.Text()

    var mpw string
    for {
        pw, _ := gopass.GetPass("Enter master password: ")
        pwHash := sha512.Sum512([]byte(pw))
        pwId := hex.encodeToString(pwHash[:8])
        if pwId == masterPwHash {
            mpw = pw
            break
        }
    }

    for scan.Scan() {
        line := strings.Split(scan.Text(), " ")
        info := new(pwInfo)
        info.alpLength := int(line[1])
        info.alphabet := line[2]

        pws[line[0]] = info
    }
    
    return pws, mpw, nil
}

func newMasterPw(pwFileName) (pwList, string, error) {
    f, err := os.Create(pwFileName)
    if err != nil {
        return nil, nil, err
    }
    defer f.Close()

    var masterPw string
    for {
        pw0, _ := gopass.GetPass("Enter new master password: ")
        pw1, _ := gopass.GetPass("Verify new master password: ")
        if pw0 == pw1 {
            masterPw = pw0
            break
        }
    }

    pwHash := sha512.Sum512([]byte(masterPw))
    pwId := hex.encodeToString(pwHash[:8])
    f.WriteString(pwId + "\n")

    return make(map[string]*pwInfo), masterPw, nil
}
