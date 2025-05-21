package srp

import (
	"crypto"
	"encoding/hex"
	"hash"
	"math/big"
	"regexp"
)

const SRP_N_LEN_1024 = 1024
const SRP_N_LEN_2048 = 2048
const SRP_N_LEN_4096 = 4096
const SRP_N_LEN_1536 = 1536

/**
srp密码交换协议参数存储对象，记录GN对，这个文件就是定义了几个gn对常量
*/
// Map of bits to <g, N> tuple
type SRPParam struct {
	G             *big.Int
	N             *big.Int
	Hash          crypto.Hash
	NLengthBits   int
	NoUserNameInX bool //在计算X值的时候是否不添加user name信息，apple的版本值是true，也就是计算x值不加username信息
}

/*
选取一个SRP参数，G的值可以是 _SRP_N_LEN_1024,_SRP_N_LEN_1536,_SRP_N_LEN_2048,_SRP_N_LEN_4096
apple使用的是_SRP_N_LEN_2048
*/
func GetSRPParam(nBitLength int) *SRPParam {
	return knownGroups[nBitLength]
}

var knownGroups map[int]*SRPParam

/*
*
初始化srp可用的参数常量
*/
func init() {

	///初始化常量辅助函数
	createSrpParam := func(G int64, nBitLength int, hash crypto.Hash, NHex string) *SRPParam {
		//初始化常量辅助函数。清理格式化的hex里面的空格，换行之类的，为了便于显示本代码里面的几个hex常量是带空格的，所以要通过此函数消除下空格
		re, _ := regexp.Compile("[^0-9a-fA-F]")
		h := re.ReplaceAll([]byte(NHex), []byte(""))
		nHexBytes, _ := hex.DecodeString(string(h))

		p := SRPParam{
			G:           big.NewInt(G),
			N:           new(big.Int),
			NLengthBits: nBitLength,
			Hash:        hash,
		}
		p.N.SetBytes(nHexBytes)
		p.NoUserNameInX = true //设置默认值，apple的版本计算x的时候不用username
		return &p
	}

	knownGroups = make(map[int]*SRPParam)

	knownGroups[SRP_N_LEN_1024] = createSrpParam(2, SRP_N_LEN_1024, crypto.SHA1, `
		EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
		9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
		8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
		7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
		FD5138FE 8376435B 9FC61D2F C0EB06E3`)

	knownGroups[SRP_N_LEN_1536] = createSrpParam(2, SRP_N_LEN_1536, crypto.SHA1, `
		9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961
		4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843
		80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B
		E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5
		6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A
		F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E
		8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB
	`)

	knownGroups[SRP_N_LEN_2048] = createSrpParam(2, SRP_N_LEN_2048, crypto.SHA256, `
		AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
		3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
		CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
		D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
		7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
		436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
		5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
		03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
		94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
		9E4AFF73
	`)

	knownGroups[SRP_N_LEN_4096] = createSrpParam(5, SRP_N_LEN_4096, crypto.SHA256, `
		FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
		8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
		302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
		A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
		49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
		FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
		670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
		180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
		3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
		04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
		B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
		1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
		BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
		E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
		99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
		04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
		233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
		D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
		FFFFFFFF FFFFFFFF
	`)
}

// -------------------上面是定义param常量，下面是对param的一些操作-------------------------------------
func (params *SRPParam) calculateA(a *big.Int) []byte {
	ANum := new(big.Int)
	ANum.Exp(params.G, a, params.N)
	return padToN(ANum, params)
}
func (params *SRPParam) calculateU(A, B *big.Int) *big.Int {
	hashU := params.Hash.New()
	ab := append(padToN(A, params), padToN(B, params)...)
	hashU.Write(ab)
	r := hashToInt(hashU)
	return r
}

// calculateS  /* Client Side S = (B - k*(g^x)) ^ (a + ux) */
func (params *SRPParam) calculateS(k, x, a, B, u *big.Int) []byte {
	BLessThan0 := B.Cmp(big.NewInt(0)) <= 0
	NLessThanB := params.N.Cmp(B) <= 0
	if BLessThan0 || NLessThanB {
		panic("invalid server-supplied 'B', must be 1..N-1")
	}
	result1 := new(big.Int)
	result1.Exp(params.G, x, params.N)

	result2 := new(big.Int)
	result2.Mul(k, result1)

	result3 := new(big.Int)
	result3.Sub(B, result2)

	result4 := new(big.Int)
	result4.Mul(u, x)

	result5 := new(big.Int)
	result5.Add(a, result4)

	result6 := new(big.Int)
	result6.Exp(result3, result5, params.N)

	result7 := new(big.Int)
	result7.Mod(result6, params.N)
	return padToN(result7, params)
}
func (params *SRPParam) calculateK(S []byte) []byte {
	hashK := params.Hash.New()
	hashK.Write(S)
	return hashK.Sum(nil)
}

// calculateX // x = SHA(s | SHA(U | ":" | p))
func (params *SRPParam) calculateX(salt, I, P []byte) *big.Int {

	h := params.Hash.New()
	if !params.NoUserNameInX {
		h.Write(I)
	}
	h.Write([]byte(":"))
	h.Write(P)
	digest := h.Sum(nil)
	h2 := params.Hash.New()

	h2.Write(salt)
	h2.Write(digest)
	x := new(big.Int)
	x.SetBytes(h2.Sum(nil))
	return x
}

// Digest digest_sha256
func (params *SRPParam) Digest(message []byte) []byte {
	h := params.Hash.New()
	h.Write(message)
	return h.Sum(nil)
}

// calculateM1 apple login M1
func (params *SRPParam) calculateM1(username, salt, A, B, K []byte) []byte {
	/*
		i = H(g) xor H(N)
		M1 = H(i) + H(I) + H(salt) + H(A) + H(B) + H(K)
		+  ==>  sha256_update
	*/
	// A,B 必须对齐，不然gg
	digestn := params.Digest(padToN(params.G, params))
	digestg := params.Digest(params.N.Bytes())
	digesti := params.Digest(username)
	hxor := make([]byte, len(digestn))
	for i := range digestn {
		hxor[i] = digestn[i] ^ digestg[i]
	}
	h := params.Hash.New()
	h.Write(hxor)
	h.Write(digesti)
	h.Write(salt)
	h.Write(A)
	h.Write(B)
	h.Write(K)
	m1 := h.Sum(nil)
	return m1
}
func (params *SRPParam) calculateM2(A, M1, K []byte) []byte {
	h := params.Hash.New()
	h.Write(A)
	h.Write(M1)
	h.Write(K)
	return h.Sum(nil)
}

// getMultiplier 计算k  k = h(n,g) ==> 在apple 算法中 k = h(n|g)  n,g 直接串联,并且按照位数对齐，不足的前面补0凑
func (params *SRPParam) getMultiplier() *big.Int {
	h := params.Hash.New()
	n := params.N.Bytes()
	g := params.G.Bytes()
	for len(g) < len(n) {
		g = append([]byte{0}, g...)
	}
	h.Write(append(n, g...))
	return hashToInt(h)
}

// ComputeVerifier returns a verifier that is calculated as described in
// Section 3 of [SRP-RFC]
func ComputeVerifier(params *SRPParam, salt, identity, password []byte) []byte {
	x := params.calculateX(salt, identity, password)
	vNum := new(big.Int)
	vNum.Exp(params.G, x, params.N)
	return padToN(vNum, params)
}

// --------------------------------------------一下是辅助函数
func hashToInt(h hash.Hash) *big.Int {
	U := new(big.Int)
	U.SetBytes(h.Sum(nil))
	return U
}

func padTo(bytes []byte, length int) []byte {
	paddingLength := length - len(bytes)
	padding := make([]byte, paddingLength, paddingLength)
	return append(padding, bytes...)
}

func padToN(number *big.Int, params *SRPParam) []byte {
	return padTo(number.Bytes(), params.NLengthBits/8)
}
