package main

import (
    "fmt"
    "flag"
    "os"
    "crypto/sha256"
    "encoding/hex"
    "encoding/base64"
    "errors"
    "bufio"
    "strings"
    "regexp"
    "code.google.com/p/gopass"
)

type pwList map[string]string

func main() {
    setPw := flag.Bool("s", false, "Set/reset master password")
    defaultPath := os.Getenv("HOME") + "/.pwdb"
    pwFileName := flag.String("f", defaultPath, "Password database file, default ~/.pwdb")
    flag.Parse()

    if *setPw {
        newMasterPw(*pwFileName)
        return
    }

    pws, master, err := getPwDb(*pwFileName)
    if err != nil {
        fmt.Println(err)
        return
    }
    
    for genPwSingleSite(pws, master, *pwFileName) {}
}

func genPwSingleSite(pws pwList, master, pwFileName string) bool {
    var siteName string
    fmt.Print("Enter site name: ")
    fmt.Scanf("%s", &siteName)
    if len(siteName) == 0 {
        return false
    }

    if siteName[0] == '?' {
        matchingSites := make([]string, 1)
        for k, _ := range pws {
            if strings.Contains(k, siteName[1:]) {
                matchingSites = append(matchingSites, k)
            }
        }
        fmt.Printf("Matching sites:\n%s\n", strings.Join(matchingSites, "\n"))
    } else if info, ok := pws[siteName]; ok {
        pwOut, err := genPw(master, siteName, info)
        if err != nil {
            fmt.Println(err)
            return true 
        }
        fmt.Println(pwOut)
    } else {
        if !confirmSiteAdd(siteName) {
            return true 
        }

        fmt.Printf("Enter u, n, s depending on password requirements: ")
        var alpChoice string
        fmt.Scanf("%s", &alpChoice)

        err := addSiteInfo(pwFileName, siteName, alpChoice)
        if err != nil {
            fmt.Println(err)
            return true
        }

        pwOut, err := genPw(master, siteName, alpChoice)
        if err != nil {
            fmt.Println(err)
            return true
        }

        fmt.Println(pwOut)
    }
    return true
}

func confirmSiteAdd(siteName string) bool {
    fmt.Printf("Site %s not recognized. Add? (y/N) ", siteName)
    var choice string
    fmt.Scanf("%s", &choice)
    return choice == "y"
}

func getPwDb(pwFileName string) (pwList, string, error) {
    if _, err := os.Stat(pwFileName); os.IsNotExist(err) {
        pws, mpw, err := newMasterPw(pwFileName)
        if err != nil {
            return nil, "", err
        }
        return pws, mpw, nil
    }

    pwFile, err := os.Open(pwFileName)
    if err != nil {
        return nil, "", errors.New(fmt.Sprintf("Error opening %s\n", pwFileName))
    }
    defer pwFile.Close()

    pws := make(map[string]string)

    scan := bufio.NewScanner(pwFile)
    scan.Scan()

    masterPwHash := scan.Text()

    var mpw string
    for {
        pw, _ := gopass.GetPass("Enter master password: ")
        pwHash := sha256.Sum256([]byte(pw))
        pwId := hex.EncodeToString(pwHash[:8])
        if pwId == masterPwHash {
            mpw = pw
            break
        }
    }

    for scan.Scan() {
        line := strings.Split(scan.Text(), " ")

        pws[line[0]] = line[1]
    }
    
    return pws, mpw, nil
}

func newMasterPw(pwFileName string) (pwList, string, error) {
    f, err := os.Create(pwFileName)
    if err != nil {
        return nil, "", err
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

    pwHash := sha256.Sum256([]byte(masterPw))
    pwId := hex.EncodeToString(pwHash[:8])
    f.WriteString(pwId + "\n")

    return make(map[string]string), masterPw, nil
}

func addSiteInfo(pwFileName, siteName, info string) error {
    if _, err := os.Stat(pwFileName); os.IsNotExist(err) {
        return errors.New("File does not exist: uhoh")
    }

    f, err := os.OpenFile(pwFileName, os.O_RDWR|os.O_APPEND, 0666)
    if err != nil {
        return err
    }
    defer f.Close()

    _, err = f.Seek(0, 2)
    if err != nil {
        return err
    }
    _, err = f.WriteString(siteName + " " + info + "\n")
    if err != nil {
        return err
    }

    return nil
}

func genPw(master, siteName, alphabet string) (string, error) {
    if m, _ := regexp.MatchString("[^uns]+", alphabet); m {
        return "", errors.New(fmt.Sprintf("Alphabet string %s makes no sense", alphabet))
    }
    encodeString := ""

    if strings.Contains(alphabet, "u") {
        encodeString += "QWERTYUIOPASDFGHJKLZXCVBNM"
    }
    if strings.Contains(alphabet, "n") {
        encodeString += "1234567890"
    }
    if strings.Contains(alphabet, "s") {
        encodeString += "!@#$%^&*()~`{}[];:<>,.?/"
    }
    encodeString += genLowers(64 - len(encodeString))

    encoder := base64.NewEncoding(encodeString)

    c1 := sha256.Sum256([]byte(master + siteName))

    s1 := encoder.EncodeToString(c1[:12])

    return s1, nil
}

func genLowers(length int) string {
    newS := make([]byte, length, length)
    for i := 0; i < length; i++ {
        newS[i] = byte(i % 26 + 97)
    }
    return string(newS)
}
