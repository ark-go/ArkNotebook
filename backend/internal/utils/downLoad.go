/*
взято у (Edd Turtle) отсюда  https://golangcode.com/download-a-file-with-progress/
*/
package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// WriteCounter подсчитывает количество записанных в него байтов. Он реализует интерфейс io.Writer
// и мы можем передать это в io.TeeReader(), который будет сообщать о ходе выполнения каждого цикла записи.
type WriteCounter struct {
	Total    uint64
	TotalPrc int
	Size     uint64
	Notify   chan *WriteCounter
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total += uint64(n)
	wc.TotalPrc = int((float64(wc.Total) / float64(wc.Size)) * 100)
	//	wc.PrintProgress()

	if wc.Notify != nil {
		wc.Notify <- wc
	}
	return n, nil
}

func (wc WriteCounter) PrintProgress() {
	// Очистить строку, используя символ возврата, чтобы вернуться к началу и удалить
	// оставшиеся символы, заполнив их пробелами
	fmt.Printf("\r%s", strings.Repeat(" ", 35))

	// Вернуться снова и вывести текущий статус загрузки
	fmt.Printf("\rDownloading... %d%% - %s (%s) complete", wc.TotalPrc, ByteCountSI(wc.Total), ByteCountIEC(wc.Total)) //humanize.Bytes(wc.Total))
}

// DownloadFile загрузит URL-адрес в локальный файл. Это эффективно, потому что
// писать по мере загрузки, а не загружать весь файл в память. Мы передаем io.TeeReader
// в Copy(), чтобы сообщить о ходе загрузки.
func DownloadFile(filepath string, url string, endDown chan bool, notify chan *WriteCounter) error {
	//var errbak error
	if endDown != nil {
		defer func() {
			endDown <- true
		}()
	}
	// ---------------------
	respS, err := http.Head(url)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	// Is our request ok?
	if respS.StatusCode != http.StatusOK {
		fmt.Println(respS.Status)
		return err
	}

	// the Header "Content-Length" will let us know
	// the total file size to download
	size, _ := strconv.ParseUint(respS.Header.Get("Content-Length"), 10, 64)

	// Создадим файл, но дадим ему расширение tmp, это означает, что мы не будем перезаписывать
	// файл, пока он не будет загружен, но мы удалим расширение tmp после загрузки.
	out, err := os.Create(filepath + ".tmp")
	if err != nil {
		return err
	}

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		out.Close()
		return err
	}
	defer resp.Body.Close()

	// Создайте наш отчет о прогрессе и передайте его для использования вместе с нашим писателем.
	counter := &WriteCounter{
		Size:   size,
		Notify: notify,
	}
	if _, err = io.Copy(out, io.TeeReader(resp.Body, counter)); err != nil {
		out.Close()
		return err
	}
	// Закрыть файл без задержки, чтобы это могло произойти до Rename()
	if err = out.Close(); err != nil {
		return err
	}
	return os.Rename(filepath+".tmp", filepath)

}
