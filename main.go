package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Binject/debug/pe"
	"github.com/fatih/color"
)

func getDLLsFromExe(exePath string) ([]string, []*pe.Section, error) {
	file, err := pe.Open(exePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	sections := file.Sections

	importedLibs, err := file.ImportedLibraries()
	if err != nil {
		fmt.Println("Ошибка при получении импортируемых библиотек:", err)
		return nil, sections, err
	}
	return importedLibs, sections, nil
}

func getDelayDLLsFromExe(exePath string) ([]string, error) {
	file, err := pe.Open(exePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var delayDir *pe.DataDirectory
	switch oh := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT {
			delayDir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT {
			delayDir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
		}
	default:
		return nil, fmt.Errorf("unknown optional header type")
	}

	if delayDir == nil || delayDir.VirtualAddress == 0 || delayDir.Size == 0 {
		return []string{}, nil // Нет delay-load импортов
	}

	var dlls []string
	rva := delayDir.VirtualAddress
	for {
		sec := findSection(file, rva)
		if sec == nil {
			break
		}
		offset := int64(rva - sec.VirtualAddress)
		entry := make([]byte, 32) // IMAGE_DELAYLOAD_DESCRIPTOR = 32 bytes
		n, err := sec.ReadAt(entry, offset)
		if err != nil || n < 32 {
			break
		}
		isZero := true
		for _, b := range entry {
			if b != 0 {
				isZero = false
				break
			}
		}
		if isZero {
			break
		}
		dllNameRVA := uint32(entry[12]) | uint32(entry[13])<<8 | uint32(entry[14])<<16 | uint32(entry[15])<<24
		name := readStringAt(file, int(dllNameRVA))
		if name != "" {
			dlls = append(dlls, name)
		}
		rva += 32
	}
	return dlls, nil
}

func getExportsFromDLL(dllPath string) ([]string, error) {
	file, err := pe.Open(dllPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if file.OptionalHeader == nil {
		return nil, fmt.Errorf("no optional header found")
	}

	var exportDir *pe.DataDirectory
	switch oh := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		exportDir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	case *pe.OptionalHeader64:
		exportDir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	default:
		return nil, fmt.Errorf("unknown optional header type")
	}

	if exportDir.VirtualAddress == 0 {
		return nil, nil // No exports
	}

	sec := findSection(file, exportDir.VirtualAddress)
	if sec == nil {
		return nil, fmt.Errorf("export section not found")
	}

	data := make([]byte, exportDir.Size)
	_, err = sec.ReadAt(data, int64(exportDir.VirtualAddress-sec.VirtualAddress))
	if err != nil {
		return nil, err
	}

	if len(data) < 40 {
		return nil, fmt.Errorf("export directory too small")
	}
	nameCount := int(uint32(data[24]) | uint32(data[25])<<8 | uint32(data[26])<<16 | uint32(data[27])<<24)
	namesRVA := int(uint32(data[32]) | uint32(data[33])<<8 | uint32(data[34])<<16 | uint32(data[35])<<24)

	names := []string{}
	for i := 0; i < nameCount; i++ {
		nameRVA := readUint32At(file, namesRVA+4*i)
		name := readStringAt(file, int(nameRVA))
		names = append(names, name)
	}
	return names, nil
}

func findSection(file *pe.File, rva uint32) *pe.Section {
	for _, sec := range file.Sections {
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
			return sec
		}
	}
	return nil
}

func readUint32At(file *pe.File, rva int) uint32 {
	sec := findSection(file, uint32(rva))
	if sec == nil {
		return 0
	}
	offset := int64(uint32(rva) - sec.VirtualAddress)
	b := make([]byte, 4)
	_, err := sec.ReadAt(b, offset)
	if err != nil {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func readStringAt(file *pe.File, rva int) string {
	sec := findSection(file, uint32(rva))
	if sec == nil {
		return ""
	}
	offset := int64(uint32(rva) - sec.VirtualAddress)
	b := make([]byte, 256)
	_, err := sec.ReadAt(b, offset)
	if err != nil {
		return ""
	}
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func getImportsFromDLL(dllPath string) ([]string, error) {
	file, err := pe.Open(dllPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	importsList, err := file.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	var imports []string
	imports = append(imports, importsList...)
	return imports, nil
}

func promptPath() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Введите путь к exe-файлу: ")
	path, _ := reader.ReadString('\n')
	return strings.TrimSpace(path)
}

func printGroupedDLLs(title string, dlls []string) {
	if len(dlls) == 0 {
		return
	}
	color.New(color.FgCyan, color.Bold).Println(title)
	for i, dll := range dlls {
		color.New(color.FgWhite).Printf("%d. %s\n", i+1, dll)
	}
	color.New(color.FgHiBlack).Println(strings.Repeat("-", 60))
}

func isApiSetDLL(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "api-ms-")
}

func isSignedDLL(path string) (bool, string) {
	cmd := exec.Command("powershell", "-Command", "Get-AuthenticodeSignature -FilePath '"+path+"' | Select-Object -ExpandProperty Status")
	output, err := cmd.Output()
	if err != nil {
		return false, "Ошибка проверки подписи"
	}
	status := strings.TrimSpace(string(output))
	if status == "Valid" {
		return true, "Подписана"
	}
	return false, status // "NotSigned", "UnknownError", "HashMismatch"
}

func clearScreen() {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func interactiveMenu(normalDLLs, apiSetDLLs []string, exePath string, sections []*pe.Section) {
	reader := bufio.NewReader(os.Stdin)
	for {
		color.New(color.FgGreen, color.Bold).Println("\nМеню:")
		color.New(color.FgYellow).Println("1. Показать все обычные DLL")
		color.New(color.FgYellow).Println("2. Показать DLL семейства api-ms-*")
		color.New(color.FgYellow).Println("3. Показать только не подписанные DLL")
		color.New(color.FgYellow).Println("4. Показать подробную информацию о DLL")
		color.New(color.FgYellow).Println("5. Показать секции файла")
		color.New(color.FgRed).Println("0. Выход")
		color.New(color.FgCyan).Print("Выберите действие: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			clearScreen()
			printGroupedDLLs("Обычные DLL:", normalDLLs)
		case "2":
			clearScreen()
			printGroupedDLLs("DLL семейства api-ms-*:", apiSetDLLs)
		case "3":
			clearScreen()
			color.New(color.FgRed, color.Bold).Println("Не подписанные DLL:")
			for i, dll := range normalDLLs {
				dllPath := filepath.Join(filepath.Dir(exePath), dll)
				if _, err := os.Stat(dllPath); err == nil {
					signed, _ := isSignedDLL(dllPath)
					if !signed {
						color.New(color.FgWhite).Printf("%d. %s\n", i+1, dll)
					}
				}
			}
			color.New(color.FgHiBlack).Println(strings.Repeat("-", 60))
		case "4":
			clearScreen()
			color.New(color.FgCyan).Print("Введите номер DLL из списка обычных DLL: ")
			numStr, _ := reader.ReadString('\n')
			numStr = strings.TrimSpace(numStr)
			num, err := strconv.Atoi(numStr)
			if err != nil || num < 1 || num > len(normalDLLs) {
				color.New(color.FgRed).Println("Некорректный номер.")
				continue
			}
			dll := normalDLLs[num-1]
			dllPath := filepath.Join(filepath.Dir(exePath), dll)
			color.New(color.FgMagenta, color.Bold).Printf("Информация о %s:\n", dll)
			signed, signStatus := isSignedDLL(dllPath)
			if signed {
				color.New(color.FgGreen).Println("   [Подписана]")
			} else {
				color.New(color.FgRed).Printf("   [Не подписана] (%s)\n", signStatus)
			}
			exports, _ := getExportsFromDLL(dllPath)
			imports, _ := getImportsFromDLL(dllPath)
			if len(exports) > 0 {
				color.New(color.FgCyan).Println("   Экспортируемые функции:")
				for _, exp := range exports {
					color.New(color.FgWhite).Println("     -", exp)
				}
			} else {
				color.New(color.FgHiBlack).Println("   Экспортируемые функции: (нет)")
			}
			if len(imports) > 0 {
				color.New(color.FgCyan).Println("   Импортируемые функции:")
				for _, imp := range imports {
					color.New(color.FgWhite).Println("     -", imp)
				}
			} else {
				color.New(color.FgHiBlack).Println("   Импортируемые функции: (нет)")
			}
			color.New(color.FgHiBlack).Println(strings.Repeat("-", 60))
		case "5":
			clearScreen()
			color.New(color.FgYellow, color.Bold).Println("Секции файла:")
			for _, sec := range sections {
				color.New(color.FgWhite).Printf("  %s (VA: 0x%X, Size: 0x%X)\n", sec.Name, sec.VirtualAddress, sec.Size)
			}
			color.New(color.FgHiBlack).Println(strings.Repeat("-", 60))
		case "0":
			color.New(color.FgRed, color.Bold).Println("Выход.")
			return
		default:
			color.New(color.FgRed).Println("Неизвестная команда.")
		}
	}
}

func printBanner() {
	banner := `

__/\\\\\\\\\\\\_____/\\\______________/\\\____________________________/\\\\\\\\\\\\_____/\\\________/\\\__/\\\\____________/\\\\__/\\\\\\\\\\\\\____/\\\\\\\\\\\\\\\____/\\\\\\\\\_____        
 _\/\\\////////\\\__\/\\\_____________\/\\\___________________________\/\\\////////\\\__\/\\\_______\/\\\_\/\\\\\\________/\\\\\\_\/\\\/////////\\\_\/\\\///////////___/\\\///////\\\___       
  _\/\\\______\//\\\_\/\\\_____________\/\\\___________________________\/\\\______\//\\\_\/\\\_______\/\\\_\/\\\//\\\____/\\\//\\\_\/\\\_______\/\\\_\/\\\_____________\/\\\_____\/\\\___      
   _\/\\\_______\/\\\_\/\\\_____________\/\\\______________/\\\\\\\\\\\_\/\\\_______\/\\\_\/\\\_______\/\\\_\/\\\\///\\\/\\\/_\/\\\_\/\\\\\\\\\\\\\/__\/\\\\\\\\\\\_____\/\\\\\\\\\\\/____     
    _\/\\\_______\/\\\_\/\\\_____________\/\\\_____________\///////////__\/\\\_______\/\\\_\/\\\_______\/\\\_\/\\\__\///\\\/___\/\\\_\/\\\/////////____\/\\\///////______\/\\\//////\\\____    
     _\/\\\_______\/\\\_\/\\\_____________\/\\\___________________________\/\\\_______\/\\\_\/\\\_______\/\\\_\/\\\____\///_____\/\\\_\/\\\_____________\/\\\_____________\/\\\____\//\\\___   
      _\/\\\_______/\\\__\/\\\_____________\/\\\___________________________\/\\\_______/\\\__\//\\\______/\\\__\/\\\_____________\/\\\_\/\\\_____________\/\\\_____________\/\\\_____\//\\\__  
       _\/\\\\\\\\\\\\/___\/\\\\\\\\\\\\\\\_\/\\\\\\\\\\\\\\\_______________\/\\\\\\\\\\\\/____\///\\\\\\\\\/___\/\\\_____________\/\\\_\/\\\_____________\/\\\\\\\\\\\\\\\_\/\\\______\//\\\_ 
        _\////////////_____\///////////////__\///////////////________________\////////////________\/////////_____\///______________\///__\///______________\///////////////__\///________\///__

`
	color.New(color.FgHiMagenta, color.Bold).Println(banner)
}

func main() {
	printBanner()
	exePath := promptPath()
	dlls, sections, err := getDLLsFromExe(exePath)
	if err != nil {
		fmt.Println("Ошибка при разборе exe:", err)
		return
	}
	delayDLLs, _ := getDelayDLLsFromExe(exePath)

	if len(dlls) == 0 && len(delayDLLs) == 0 {
		fmt.Println("Импортируемые DLL не найдены.")
		return
	}

	var apiSetDLLs, normalDLLs []string
	for _, dll := range dlls {
		if isApiSetDLL(dll) {
			apiSetDLLs = append(apiSetDLLs, dll)
		} else {
			normalDLLs = append(normalDLLs, dll)
		}
	}

	interactiveMenu(normalDLLs, apiSetDLLs, exePath, sections)

	if len(delayDLLs) > 0 {
		var apiSetDelayDLLs, normalDelayDLLs []string
		for _, dll := range delayDLLs {
			if isApiSetDLL(dll) {
				apiSetDelayDLLs = append(apiSetDelayDLLs, dll)
			} else {
				normalDelayDLLs = append(normalDelayDLLs, dll)
			}
		}
		fmt.Println("Delay-load импортируемые DLL:")
		printGroupedDLLs("Обычные delay-load DLL:", normalDelayDLLs)
		printGroupedDLLs("Delay-load DLL семейства api-ms-*:", apiSetDelayDLLs)
	} else {
		fmt.Println("Delay-load импортируемые DLL не обнаружены.")
	}
}
