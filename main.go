package main

import (
	"bufio"
	"fmt"
	"os"
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

func main() {
	exePath := promptPath()
	dlls, err := getDLLsFromExe(exePath)
	if err != nil {
		fmt.Println("Ошибка при разборе exe:", err)
		return
	}
	if len(dlls) == 0 {
		fmt.Println("Импортируемые DLL не найдены.")
		return
	}
	fmt.Println("Импортируемые DLL:")
	for i, dll := range dlls {
		fmt.Printf("%d. %s\n", i+1, dll)
		dllPath := filepath.Join(filepath.Dir(exePath), dll)
		if _, err := os.Stat(dllPath); err == nil {
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
}
