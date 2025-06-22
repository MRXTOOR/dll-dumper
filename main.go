package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Binject/debug/pe"
)

func getDLLsFromExe(exePath string) ([]string, error) {
	file, err := pe.Open(exePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fmt.Println("DEBUG: Секции файла:")
	for _, sec := range file.Sections {
		fmt.Printf("  %s (VA: 0x%X, Size: 0x%X)\n", sec.Name, sec.VirtualAddress, sec.Size)
	}

	importedLibs, err := file.ImportedLibraries()
	if err != nil {
		fmt.Println("Ошибка при получении импортируемых библиотек:", err)
		return nil, err
	}
	fmt.Println("DEBUG: импортируемые библиотеки:", importedLibs)
	return importedLibs, nil
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
	fmt.Println(title)
	for i, dll := range dlls {
		fmt.Printf("%d. %s\n", i+1, dll)
	}
	fmt.Println(strings.Repeat("-", 60))
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

func main() {
	exePath := promptPath()
	dlls, err := getDLLsFromExe(exePath)
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

	fmt.Println("Импортируемые DLL:")
	printGroupedDLLs("Обычные DLL:", normalDLLs)
	printGroupedDLLs("DLL семейства api-ms-*:", apiSetDLLs)

	for i, dll := range normalDLLs {
		fmt.Printf("%d. %s\n", i+1, dll)
		dllPath := filepath.Join(filepath.Dir(exePath), dll)
		if _, err := os.Stat(dllPath); err == nil {
			signed, signStatus := isSignedDLL(dllPath)
			if signed {
				fmt.Println("   [Подписана]")
			} else {
				fmt.Printf("   [Не подписана] (%s)\n", signStatus)
			}
			exports, _ := getExportsFromDLL(dllPath)
			imports, _ := getImportsFromDLL(dllPath)

			if len(exports) > 0 {
				fmt.Println("   Экспортируемые функции:")
				for _, exp := range exports {
					fmt.Println("     -", exp)
				}
			} else {
				fmt.Println("   Экспортируемые функции: (нет)")
			}

			if len(imports) > 0 {
				fmt.Println("   Импортируемые функции:")
				for _, imp := range imports {
					fmt.Println("     -", imp)
				}
			} else {
				fmt.Println("   Импортируемые функции: (нет)")
			}
		} else {
			fmt.Println("   (Файл DLL не найден рядом с exe)")
		}
		fmt.Println(strings.Repeat("-", 60))
	}

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
