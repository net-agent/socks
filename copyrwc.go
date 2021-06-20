package socks

import (
	"io"
	"sync"
)

func LinkReadWriteCloser(a, b io.ReadWriteCloser) (a2bN, b2aN int64, err error) {
	var wg sync.WaitGroup
	var once sync.Once

	clean := func(copyErr error) {
		if copyErr != nil {
			once.Do(func() {
				err = copyErr
			})
		}
		a.Close()
		b.Close()
		wg.Done()
	}

	wg.Add(1)
	go func() {
		var cpErr error
		b2aN, cpErr = io.Copy(a, b)
		clean(cpErr)
	}()

	wg.Add(1)
	go func() {
		var cpErr error
		a2bN, err = io.Copy(b, a)
		clean(cpErr)
	}()

	wg.Wait()
	return a2bN, b2aN, err
}
