package crypto

// NewCryptForTest returns a Crypt whose IV struct and fake signature are set
// directly, marked initialised when ivStruct is not empty.
func NewCryptForTest(ivStruct, fakeSig []byte) *Crypt {
	tc := NewCrypt(nil)
	tc.ivStruct = ivStruct
	copy(tc.fakeSig[:], fakeSig)
	if len(ivStruct) > 0 {
		tc.initComplete.Store(true)
	}

	return tc
}

// IVStructLenForTest returns the IV struct's length.
func (tc *Crypt) IVStructLenForTest() int {
	tc.keyMu.Lock()
	defer tc.keyMu.Unlock()

	return len(tc.ivStruct)
}
