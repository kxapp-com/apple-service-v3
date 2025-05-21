package srp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
)

type SRPClient struct {
	Params     *SRPParam
	Secret1    *big.Int
	Multiplier *big.Int
	A          *big.Int
	X          *big.Int
	M1         []byte
	M2         []byte
	K          []byte
	u          *big.Int
	s          *big.Int
}

func NewSRPClient(param *SRPParam, a []byte) *SRPClient {
	if len(a) == 0 {
		a = make([]byte, 32)
		rand.Read(a)
	}
	multiplier := param.getMultiplier()
	secret1Int := intFromBytes(a)
	Ab := param.calculateA(secret1Int)
	A := intFromBytes(Ab)
	return &SRPClient{
		Params:     param,
		Multiplier: multiplier,
		Secret1:    secret1Int,
		A:          A,
	}
}

// ProcessClientChanllenge username,password,salt,B  计算K 和M1
func (srpClient *SRPClient) ProcessClientChanllenge(username, password, salt, B []byte) {
	srpClient.X = srpClient.Params.calculateX(salt, username, password)
	bigB := intFromBytes(B)
	u := srpClient.Params.calculateU(srpClient.A, bigB)
	k := srpClient.Multiplier
	S := srpClient.Params.calculateS(k, srpClient.X, srpClient.Secret1, bigB, u)
	srpClient.K = srpClient.Params.calculateK(S)
	srpClient.u = u
	srpClient.s = intFromBytes(S)
	A := padToN(srpClient.A, srpClient.Params)
	srpClient.M1 = srpClient.Params.calculateM1(username, salt, A, B, srpClient.K)
	srpClient.M2 = srpClient.Params.calculateM2(A, srpClient.M1, srpClient.K)
}

func (srpClient *SRPClient) GetPaddedA() []byte {
	return padToN(srpClient.A, srpClient.Params)
}

func (srpClient *SRPClient) GetA() []byte {
	return srpClient.A.Bytes()
}
func (srpClient *SRPClient) GetM1() []byte {
	return srpClient.M1
}

func (srpClient *SRPClient) GetSessionKey() []byte {
	return srpClient.K
}

func (srpClient *SRPClient) CheckM2(M2 []byte) error {
	if !bytes.Equal(srpClient.M2, M2) {
		return errors.New("M2 didn't check")
	} else {
		return nil
	}
}
func intFromBytes(bytes []byte) *big.Int {
	i := new(big.Int)
	i.SetBytes(bytes)
	return i
}
