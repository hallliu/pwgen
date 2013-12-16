package main

import (
    "fmt"
    "flag"
    "os"
    "crypto/sha512"
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

    if *setPw {
        newMasterPw(*pwFileName)
        return
    }

    pws, master, err := getPwDb(*pwFileName)
    if err != nil {
        fmt.Println(err)
        return
    }

    var siteName string
    fmt.Print("Enter site name: ")
    fmt.Scanf("%s\n", siteName)

    if info := pws[siteName]; info != "" {
        pwOut, err := genPw(master, siteName, info)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println(pwOut)
    } else {
        fmt.Printf("Enter u, n, s depending on password requirements: ")
        var alpChoice string
        fmt.Scanf("%s\n", alpChoice)

        err := addSiteInfo(*pwFileName, siteName, alpChoice)
        if err != nil {
            fmt.Println(err)
            return
        }

        pwOut, err := genPw(master, siteName, alpChoice)
        if err != nil {
            fmt.Println(err)
            return
        }

        fmt.Println(pwOut)
        return
    }
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
        pwHash := sha512.Sum512([]byte(pw))
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

    pwHash := sha512.Sum512([]byte(masterPw))
    pwId := hex.EncodeToString(pwHash[:8])
    f.WriteString(pwId + "\n")

    return make(map[string]string), masterPw, nil
}

func addSiteInfo(pwFileName, siteName, info string) error {
    if _, err := os.Stat(pwFileName); os.IsNotExist(err) {
        return errors.New("File does not exist: uhoh")
    }

    f, err := os.Open(pwFileName)
    if err != nil {
        return err
    }
    defer f.Close()

    _, err = f.Seek(0, 2)
    if err != nil {
        return err
    }
    _, err = f.WriteString(siteName + info + "\n")
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

    if strings.Contains("u", alphabet) {
        encodeString += "QWERTYUIOPASDFGHJKLZXCVBNM"
    }
    if strings.Contains("n", alphabet) {
        encodeString += "1234567890"
    }
    if strings.Contains("s", alphabet) {
        encodeString += "!@#$%^&*()~`{}[];:<>,.?/"
    }
    encodeString += genLowers(64 - len(encodeString))

    encoder := base64.NewEncoding(encodeString)

    c1 := sha512.Sum512([]byte(master + siteName))
    c2 := sha512.Sum512([]byte(siteName + master))

    s1 := encoder.EncodeToString(c1[:])
    s2 := encoder.EncodeToString(c2[:])

    return s1 + s2, nil
}

func genLowers(length int) string {
    newS := make([]byte, length, length)
    for i := 0; i < length; i++ {
        newS[i] = byte(i % 26 + length)
    }
    return string(newS)
}
