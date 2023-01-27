package utils

// Загружаем переменные в Environment из файла .env
import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/joho/godotenv"
)

var ExecDir = GetExecPath()
var F = loadEnvFile(ExecDir) // запуск при загрузке пакета

// путь к  файлу .env
func loadEnvFile(path string) string {

	pathEnv := filepath.Join(path, ".env")
	//pathEnv := path + ".env"
	if err := godotenv.Load(pathEnv); err != nil {
		log.Fatal("Ошибка: Не найден .env файл: ", pathEnv)
	}
	color.Green("Путь к .env: %s", pathEnv)
	return ""
}

// Получим каталог exe-шника
func GetExecPath() string {
	// путь к исполняемому файлу
	path, err := os.Executable()
	if err != nil {
		log.Panicln("Error GetExecPath:", err)
	}
	// проверка на символическую ссылку
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		log.Panicln("Error GetExecPath:", err)
	}
	path = filepath.Dir(path)
	return path
}

// Перевод byte int64 в string Kb Mb Tb и тд SI (1000 bytes in a kilobyte)
func ByteCountSI[T uint64 | int64](b T) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := T(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// Перевод byte int64 в string KiB Mib TiB и тд IEC (1024 bytes in a kibibyte)
//
//	func ByteCountIEC(b int64) string {
//		const unit = 1024
//		if b < unit {
//			return fmt.Sprintf("%d B", b)
//		}
//		div, exp := int64(unit), 0
//		for n := b / unit; n >= unit; n /= unit {
//			div *= unit
//			exp++
//		}
//		return fmt.Sprintf("%.1f %ciB",
//			float64(b)/float64(div), "KMGTPE"[exp])
//	}
func ByteCountIEC[T uint64 | int64](b T) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := T(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}

/*
Поддержка синтаксического анализа количества байтов SI и IEC.
Поддержка форматирования количества байтов SI и IEC.

Базовое количество SI 1000, единицы измерения B, kB, MB, GB, TB, PB, EB, ZB, YB
Базовое количество IEC составляет 1024, единицы измерения: B, KiB, MiB, GiB, TiB, PiB, EiB, ZiB, YiB
По умолчанию используется форматирование единиц СИ.
*/
