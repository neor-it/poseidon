package main

import (
	"log"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"golang.org/x/crypto/sha3"
)

func TestHash(t *testing.T) {
	type testData struct {
		name string
		msg  []byte
	}

	tests := []testData{
		{name: "Test 0", msg: []byte("Hi!")},
		{name: "Test 1", msg: []byte("hello world")},
		{name: "Test 2", msg: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.")},
		{name: "Test 3", msg: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.")},
		{name: "Test 4", msg: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Neque sodales ut etiam sit amet nisl purus in. Arcu risus quis varius quam quisque id. Adipiscing diam donec adipiscing tristique risus. Risus viverra adipiscing at in tellus. Sagittis id consectetur purus ut faucibus pulvinar elementum integer. Lorem mollis aliquam ut porttitor leo a diam sollicitudin tempor. Scelerisque felis imperdiet proin fermentum leo vel orci. Erat pellentesque adipiscing commodo elit at imperdiet. Auctor neque vitae tempus quam. Est pellentesque elit ullamcorper dignissim cras tincidunt. Ullamcorper morbi tincidunt ornare massa. Sollicitudin nibh sit amet commodo nulla facilisi. Turpis massa sed elementum tempus egestas sed sed risus. Libero justo laoreet sit amet. Morbi non arcu risus quis varius quam quisque id. Eget nulla facilisi etiam dignissim. Sed id semper risus in hendrerit. Duis at consectetur lorem donec massa sapien faucibus et. Non pulvinar neque laoreet suspendisse. Nec nam aliquam sem et tortor consequat id porta. Gravida quis blandit turpis cursus in hac habitasse platea dictumst. Adipiscing vitae proin sagittis nisl rhoncus. Tincidunt vitae semper quis lectus nulla at volutpat diam. Vitae justo eget magna fermentum iaculis. Amet consectetur adipiscing elit duis tristique sollicitudin nibh sit. Vel quam elementum pulvinar etiam. Ullamcorper sit amet risus nullam eget felis eget nunc. Turpis egestas sed tempus urna et pharetra. Fermentum dui faucibus in ornare quam viverra orci sagittis. Scelerisque felis imperdiet proin fermentum leo vel orci. Lorem donec massa sapien faucibus. Suscipit adipiscing bibendum est ultricies integer quis. Morbi tincidunt ornare massa eget egestas purus viverra accumsan. Ut lectus arcu bibendum at varius. Diam quam nulla porttitor massa id neque aliquam. Sit amet consectetur adipiscing elit duis tristique. Massa enim nec dui nunc mattis enim ut tellus elementum. Id donec ultrices tincidunt arcu non. Imperdiet dui accumsan sit amet nulla. Odio morbi quis commodo odio aenean. Sagittis purus sit amet volutpat. Enim praesent elementum facilisis leo vel fringilla est ullamcorper eget. Amet tellus cras adipiscing enim eu turpis. Porta nibh venenatis cras sed felis eget velit aliquet sagittis. Aliquam sem fringilla ut morbi tincidunt augue interdum. In eu mi bibendum neque egestas congue quisque egestas diam. Risus nullam eget felis eget nunc lobortis mattis. Morbi enim nunc faucibus a pellentesque sit amet. Orci porta non pulvinar neque laoreet. Vitae tempus quam pellentesque nec nam aliquam sem. Diam in arcu cursus euismod. Suspendisse potenti nullam ac tortor vitae purus faucibus. Facilisis leo vel fringilla est ullamcorper eget. Platea dictumst vestibulum rhoncus est. Lectus mauris ultrices eros in cursus turpis massa tincidunt dui. Nulla at volutpat diam ut venenatis. Velit ut tortor pretium viverra suspendisse potenti nullam ac tortor. Elit at imperdiet dui accumsan sit amet nulla facilisi. Dignissim sodales ut eu sem. Ligula ullamcorper malesuada proin libero nunc. Mollis aliquam ut porttitor leo a diam. In nisl nisi scelerisque eu ultrices. Et molestie ac feugiat sed lectus vestibulum mattis. Tellus at urna condimentum mattis pellentesque id nibh tortor. Et netus et malesuada fames ac turpis. Pulvinar neque laoreet suspendisse interdum consectetur libero id. Est ultricies integer quis auctor elit sed vulputate mi. Nunc id cursus metus aliquam eleifend mi in nulla posuere. Dapibus ultrices in iaculis nunc. Vitae tortor condimentum lacinia quis vel. Facilisi cras fermentum odio eu. Aliquet enim tortor at auctor. Eu volutpat odio facilisis mauris sit amet. Purus sit amet volutpat consequat mauris. Gravida in fermentum et sollicitudin ac. Bibendum at varius vel pharetra vel turpis nunc. Risus at ultrices mi tempus imperdiet nulla malesuada. Velit dignissim sodales ut eu sem integer. Adipiscing at in tellus integer feugiat scelerisque varius. Nulla facilisi nullam vehicula ipsum a arcu cursus vitae. Interdum velit euismod in pellentesque massa placerat duis ultricies. Mi bibendum neque egestas congue quisque egestas diam in arcu. Condimentum mattis pellentesque id nibh tortor. Mollis nunc sed id semper risus in hendrerit gravida. Varius sit amet mattis vulputate. Ultricies leo integer malesuada nunc. Tempus quam pellentesque nec nam aliquam sem et. Fusce id velit ut tortor pretium viverra suspendisse potenti nullam. Ultrices mi tempus imperdiet nulla malesuada. Dolor sit amet consectetur adipiscing elit duis tristique. Ipsum dolor sit amet consectetur adipiscing elit duis. Etiam erat velit scelerisque in dictum non. Euismod in pellentesque massa placerat duis. Nec tincidunt praesent semper feugiat. Id nibh tortor id aliquet lectus proin nibh nisl condimentum. Venenatis tellus in metus vulputate eu scelerisque felis. Rhoncus mattis rhoncus urna neque viverra justo. Nulla facilisi morbi tempus iaculis urna id. Ipsum dolor sit amet consectetur adipiscing elit duis tristique sollicitudin.")},
	}

	for _, testdata := range tests {
		t.Run(testdata.name, func(test *testing.T) {
			log.Printf("================ %s ================", testdata.name)
			log.Printf("Message length: %d bytes", len(testdata.msg))

			var poseidonHash *big.Int
			var hashSha3 []byte

			var m runtime.MemStats

			runtime.ReadMemStats(&m)

			start := time.Now()
			poseidonHash = HashBytes(testdata.msg)
			timeUsed := time.Since(start)

			runtime.ReadMemStats(&m)
			memAlloc := m.Alloc

			log.Printf("Poseidon hash: %s", poseidonHash)
			log.Printf("Poseidon hash length: %d bytes", len(poseidonHash.Bytes()))
			log.Printf("Hashing in Poseidon took %s", timeUsed)
			log.Printf("Alloc = %v bytes", memAlloc)

			start = time.Now()
			hashSha3 = toSHA3(testdata.msg)
			timeUsed = time.Since(start)

			log.Printf("SHA-3 hash: %d", hashSha3)
			log.Printf("SHA-3 hash length: %d bytes", len(hashSha3))
			log.Printf("Hashing in SHA-3 took %s", timeUsed)

			pmsg, _ := poseidon.HashBytes(testdata.msg)

			log.Println("Hash in library implementation: ", pmsg)
		})
	}
}

func toSHA3(msg []byte) []byte {
	sha3Hash := sha3.New256()
	sha3Hash.Write(msg)
	hashSha3 := sha3Hash.Sum(nil)
	return hashSha3
}
