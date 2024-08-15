package main

import (
	"bytes"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

const (
	NROUNDSF = 8  // кількість раундів
	INPUTS   = 16 // кількість елементів в масиві, який передається в функцію Hash
	SBLOCK   = 31 // розмір блоку, на який розбивається вхідний зріз байтів
)

var NROUNDSP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}                                   // раунди які використовуються для кожної кількості елементів в масиві, який передається в функцію Hash
var q, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10) // константа q (за допомогою якої відбувається обчислення по модулю q)
var big5int *big.Int = big.NewInt(5)                                                                                   // константа 5 для піднесення до ступеню 5

func addRoundKeys(state []*big.Int, constants []*big.Int, r int) {
	var wg sync.WaitGroup

	for i := range state {
		wg.Add(1) // Додаємо горутину до групи
		go func(i int) {
			defer wg.Done() // Позначаємо горутину як завершену
			state[i].Add(state[i], constants[r+i]).Mod(state[i], q)
		}(i)
	}

	wg.Wait() // Очікуємо на завершення всіх горутин
}

// mix - функція перемішування елементів state
func mix(state []*big.Int, countElements int, matr [][]*big.Int) []*big.Int {
	newState := make([]*big.Int, countElements)
	cache := make([]*big.Int, len(matr))
	mul := new(big.Int)

	initCh := make(chan int, len(newState)) // буферизований канал для ініціалізації newState
	constCh := make(chan int, len(matr))    // буферизований канал для додавання констант

	for i := range newState {
		initCh <- i // додаємо індекси до каналу для ініціалізації newState
	}
	close(initCh)

	for i := range matr {
		constCh <- i // додаємо індекси до каналу для додавання констант
	}
	close(constCh)

	var wg sync.WaitGroup

	for i := 0; i < len(newState); i++ {
		wg.Add(1)
		go func() { // горутина для ініціалізації newState
			defer wg.Done()
			for i := range initCh {
				newState[i] = big.NewInt(0)
			}
		}()
	}

	for i := 0; i < len(matr); i++ {
		wg.Add(1)
		go func() { // горутина для додавання констант
			defer wg.Done()
			for i := range constCh {
				cache[i] = new(big.Int).SetInt64(0)
			}
		}()
	}

	wg.Wait() // чекаємо завершення всіх горутин

	for i := 0; i < countElements; i++ {
		for j, p := range matr {
			cache[j].Mul(p[i], state[j])
		}

		for _, c := range cache {
			mul.Add(mul, c)
		}

		newState[i].Mod(mul, q)
		mul.SetInt64(0)
	}

	return newState
}

var bigIntPool = sync.Pool{
	New: func() interface{} {
		return new(big.Int)
	},
}

func exp5(x *big.Int) *big.Int {
	big5int := big.NewInt(5)

	// Використання буферного пулу для отримання об'єкта big.Int (для економії пам'яті)
	buf := bigIntPool.Get().(*big.Int)
	defer bigIntPool.Put(buf)

	// піднесення до ступеню 5 елементу x по модулю q
	buf.Exp(x, big5int, q)

	return buf
}

// exp5state - функція піднесення до ступеню 5 кожного елементу масиву state
func exp5state(state []*big.Int) []*big.Int {
	var wg sync.WaitGroup

	for i := range state {
		wg.Add(1)        // Додаємо горутину до групи
		go func(i int) { // Горутина для кожного елементу state для паралельного виконання піднесення до ступеню 5
			defer wg.Done() // Позначаємо горутину як завершену
			state[i] = new(big.Int).Exp(state[i], big5int, q)
		}(i)
	}

	wg.Wait() // Очікуємо на завершення всіх горутин

	return state
}

// Hash - функція гешування вхідного масиву елементів типу *big.Int в один елемент типу *big.Int
func Hash(input []*big.Int) *big.Int {
	countElements := len(input) + 1

	nRoundsF := NROUNDSF
	nRoundsP := NROUNDSP[countElements-2]

	// константи для даної кількості елементів в масиві, який передається в функцію Hash
	C := c.c[countElements-2]
	S := c.s[countElements-2]
	M := c.m[countElements-2]
	P := c.p[countElements-2]

	state := make([]*big.Int, countElements)
	state[0] = big.NewInt(0)
	copy(state[1:], input)

	addRoundKeys(state, C, 0)

	for i := 0; i < nRoundsF/2-1; i++ {
		state = exp5state(state)                    // піднесення до ступеню 5 кожного елементу масиву state
		addRoundKeys(state, C, (i+1)*countElements) // додавання константи до кожного елементу масиву state
		state = mix(state, countElements, M)        // перемішування елементів масиву state за допомогою матриці M
	}

	state = exp5state(state)
	addRoundKeys(state, C, (nRoundsF/2)*countElements)
	state = mix(state, countElements, P)

	mul := big.NewInt(0)
	newState0 := big.NewInt(0)

	for i := 0; i < nRoundsP; i++ {
		state[0] = exp5(state[0])
		state[0].Add(state[0], C[(nRoundsF/2+1)*countElements+i]) // додавання константи до елементу state[0]
		state[0].Mod(state[0], q)

		mul.SetInt64(0)
		newState0.SetInt64(0)

		for j := range state {
			mul.Mul(S[(countElements*2-1)*i+j], state[j])
			newState0.Add(newState0, mul)
			newState0.Mod(newState0, q)
		}

		for k := 1; k < countElements; k++ {
			mul.SetInt64(0)
			state[k].Add(state[k], mul.Mul(state[0], S[(countElements*2-1)*i+countElements+k-1]))
			state[k].Mod(state[k], q)
		}
		state[0] = newState0
	}

	for i := 0; i < nRoundsF/2-1; i++ {
		state = exp5state(state)
		addRoundKeys(state, C, (nRoundsF/2+1)*countElements+nRoundsP+i*countElements)
		state = mix(state, countElements, M)
	}

	state = exp5state(state)
	state = mix(state, countElements, M)

	return state[0]
}

// HashBytes - функція гешування вхідного масиву байтів в один елемент типу *big.Int
func HashBytes(msg []byte) *big.Int {
	var inputs [INPUTS]*big.Int // масив елементів типу *big.Int, які передаються в функцію Hash

	for j := range inputs { // ініціалізація масиву елементів типу *big.Int нулями
		inputs[j] = new(big.Int)
	}

	var hash *big.Int

	k := 0 // індекс елемента масиву елементів типу *big.Int, який заповнюється байтами з вхідного масиву байтів

	for i := 0; i < len(msg)/SBLOCK; i++ { // заповнення масиву елементів типу *big.Int байтами з вхідного масиву байтів
		inputs[k].SetBytes(msg[SBLOCK*i : SBLOCK*(i+1)]) // заповнення елемента масиву елементів типу *big.Int байтами з вхідного масиву байтів
		if k == INPUTS-1 {                               // якщо масив елементів типу *big.Int заповнений, то викликаємо функцію Hash
			hash = Hash(inputs[:])

			inputs[0].Set(hash)           // перший елемент масиву елементів типу *big.Int стає результатом виклику функції Hash
			for j := 1; j < INPUTS; j++ { // інші елементи масиву елементів типу *big.Int ініціалізуються нулями
				inputs[j].SetUint64(0)
			}
			k = 1
		} else {
			k++
		}
	}

	// заповнення останнього елемента масиву елементів типу *big.Int байтами з вхідного масиву байтів
	if len(msg)%SBLOCK != 0 {
		var buf [SBLOCK]byte                         // буфер для копіювання останніх байтів з вхідного масиву байтів
		copy(buf[:], msg[(len(msg)/SBLOCK)*SBLOCK:]) // копіювання останніх байтів з вхідного масиву байтів в буфер
		inputs[k].SetBytes(buf[:])                   // заповнення елемента масиву елементів типу *big.Int байтами з буфера
	}

	hash = Hash(inputs[:]) // виклик функції Hash

	return hash
}

func main() {
	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Neque sodales ut etiam sit amet nisl purus in. Arcu risus quis varius quam quisque id. Adipiscing diam donec adipiscing tristique risus. Risus viverra adipiscing at in tellus. Sagittis id consectetur purus ut faucibus pulvinar elementum integer. Lorem mollis aliquam ut porttitor leo a diam sollicitudin tempor. Scelerisque felis imperdiet proin fermentum leo vel orci. Erat pellentesque adipiscing commodo elit at imperdiet. Auctor neque vitae tempus quam. Est pellentesque elit ullamcorper dignissim cras tincidunt. Ullamcorper morbi tincidunt ornare massa. Sollicitudin nibh sit amet commodo nulla facilisi. Turpis massa sed elementum tempus egestas sed sed risus. Libero justo laoreet sit amet. Morbi non arcu risus quis varius quam quisque id. Eget nulla facilisi etiam dignissim. Sed id semper risus in hendrerit. Duis at consectetur lorem donec massa sapien faucibus et. Non pulvinar neque laoreet suspendisse. Nec nam aliquam sem et tortor consequat id porta. Gravida quis blandit turpis cursus in hac habitasse platea dictumst. Adipiscing vitae proin sagittis nisl rhoncus. Tincidunt vitae semper quis lectus nulla at volutpat diam. Vitae justo eget magna fermentum iaculis. Amet consectetur adipiscing elit duis tristique sollicitudin nibh sit. Vel quam elementum pulvinar etiam. Ullamcorper sit amet risus nullam eget felis eget nunc. Turpis egestas sed tempus urna et pharetra. Fermentum dui faucibus in ornare quam viverra orci sagittis. Scelerisque felis imperdiet proin fermentum leo vel orci. Lorem donec massa sapien faucibus. Suscipit adipiscing bibendum est ultricies integer quis. Morbi tincidunt ornare massa eget egestas purus viverra accumsan. Ut lectus arcu bibendum at varius. Diam quam nulla porttitor massa id neque aliquam. Sit amet consectetur adipiscing elit duis tristique. Massa enim nec dui nunc mattis enim ut tellus elementum. Id donec ultrices tincidunt arcu non. Imperdiet dui accumsan sit amet nulla. Odio morbi quis commodo odio aenean. Sagittis purus sit amet volutpat. Enim praesent elementum facilisis leo vel fringilla est ullamcorper eget. Amet tellus cras adipiscing enim eu turpis. Porta nibh venenatis cras sed felis eget velit aliquet sagittis. Aliquam sem fringilla ut morbi tincidunt augue interdum. In eu mi bibendum neque egestas congue quisque egestas diam. Risus nullam eget felis eget nunc lobortis mattis. Morbi enim nunc faucibus a pellentesque sit amet. Orci porta non pulvinar neque laoreet. Vitae tempus quam pellentesque nec nam aliquam sem. Diam in arcu cursus euismod. Suspendisse potenti nullam ac tortor vitae purus faucibus. Facilisis leo vel fringilla est ullamcorper eget. Platea dictumst vestibulum rhoncus est. Lectus mauris ultrices eros in cursus turpis massa tincidunt dui. Nulla at volutpat diam ut venenatis. Velit ut tortor pretium viverra suspendisse potenti nullam ac tortor. Elit at imperdiet dui accumsan sit amet nulla facilisi. Dignissim sodales ut eu sem. Ligula ullamcorper malesuada proin libero nunc. Mollis aliquam ut porttitor leo a diam. In nisl nisi scelerisque eu ultrices. Et molestie ac feugiat sed lectus vestibulum mattis. Tellus at urna condimentum mattis pellentesque id nibh tortor. Et netus et malesuada fames ac turpis. Pulvinar neque laoreet suspendisse interdum consectetur libero id. Est ultricies integer quis auctor elit sed vulputate mi. Nunc id cursus metus aliquam eleifend mi in nulla posuere. Dapibus ultrices in iaculis nunc. Vitae tortor condimentum lacinia quis vel. Facilisi cras fermentum odio eu. Aliquet enim tortor at auctor. Eu volutpat odio facilisis mauris sit amet. Purus sit amet volutpat consequat mauris. Gravida in fermentum et sollicitudin ac. Bibendum at varius vel pharetra vel turpis nunc. Risus at ultrices mi tempus imperdiet nulla malesuada. Velit dignissim sodales ut eu sem integer. Adipiscing at in tellus integer feugiat scelerisque varius. Nulla facilisi nullam vehicula ipsum a arcu cursus vitae. Interdum velit euismod in pellentesque massa placerat duis ultricies. Mi bibendum neque egestas congue quisque egestas diam in arcu. Condimentum mattis pellentesque id nibh tortor. Mollis nunc sed id semper risus in hendrerit gravida. Varius sit amet mattis vulputate. Ultricies leo integer malesuada nunc. Tempus quam pellentesque nec nam aliquam sem et. Fusce id velit ut tortor pretium viverra suspendisse potenti nullam. Ultrices mi tempus imperdiet nulla malesuada. Dolor sit amet consectetur adipiscing elit duis tristique. Ipsum dolor sit amet consectetur adipiscing elit duis. Etiam erat velit scelerisque in dictum non. Euismod in pellentesque massa placerat duis. Nec tincidunt praesent semper feugiat. Id nibh tortor id aliquet lectus proin nibh nisl condimentum. Venenatis tellus in metus vulputate eu scelerisque felis. Rhoncus mattis rhoncus urna neque viverra justo. Nulla facilisi morbi tempus iaculis urna id. Ipsum dolor sit amet consectetur adipiscing elit duis tristique sollicitudin.")

	startTime := time.Now()

	hash := HashBytes(msg)
	log.Printf("Time: %s", time.Since(startTime))
	log.Printf("[This implementation] Hash %s", hash)

	startTime = time.Now()

	libHash, _ := poseidon.HashBytes(msg)
	log.Printf("Time: %s", time.Since(startTime))
	log.Printf("[Library implementation] Hash of %s", libHash)

	if !bytes.Equal(hash.Bytes(), libHash.Bytes()) {
		log.Printf("Hashes are not equal")
	}
}
