package main

import (
	"flag"
	"fmt"
	"time"
	// "math"
	// "encoding/json"
	// "log"
	// "os"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/ckks/bootstrapping"
	//ckksAdvanced "github.com/tuneinsight/lattigo/v4/ckks/advanced"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	// "github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	//"github.com/tuneinsight/lattigo/v4/utils"
)

func main() {

	flag.Parse()
	now := time.Now()


	ckksParamsResidualLit := ckks.ParametersLiteral{
		LogN:     13,                                                // Log2 of the ringdegree
		LogSlots: 12,                                                // Log2 of the number of slots
		LogQ:     []int{55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40}, // Log2 of the ciphertext prime moduli
		LogP:     []int{61, 61, 61, 61},                             // Log2 of the key-switch auxiliary prime moduli
		LogScale: 40,                                                // Log2 of the scale
		H:        192,                                               // Hamming weight of the secret
	}

	btpParametersLit := bootstrapping.ParametersLiteral{}

	bits, err := btpParametersLit.BitConsumption()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Bootstrapping depth (bits): %d\n", bits)

	// This generate ckks.Parameters, with the NTT tables and other pre-computations from the ckks.ParametersLiteral (which is only a template).
	paramsN12, err := ckks.NewParametersFromLiteral(ckksParamsResidualLit)
	if err != nil {
		panic(err)
	}
	// paramsN12_tmp, err_tmp := rlwe.NewParametersFromLiteral(ckksParamsLit)
	// if err_tmp != nil {
	// 	panic(err_tmp)
	// }

	// Scheme context and keys
	kgenN12 := ckks.NewKeyGenerator(paramsN12)
	skN12, _ := kgenN12.GenKeyPair()
	//skN12 := kgenN12.GenSecretKey()
	encoderN12 := ckks.NewEncoder(paramsN12)
	encryptorN12 := ckks.NewEncryptor(paramsN12, skN12)
	_ = ckks.NewDecryptor(paramsN12, skN12)
	fmt.Printf("Gen sk/pk Done(%s)\n", time.Since(now))
	now = time.Now()

	kgenN12_2 := ckks.NewKeyGenerator(paramsN12)
	//skN12_2 := kgenN12_2.GenSecretKey()
	skN12_2, pkN12_2 := kgenN12_2.GenKeyPair()
	encoderN12_2 := ckks.NewEncoder(paramsN12)
	encryptorN12_2 := ckks.NewEncryptor(paramsN12, skN12_2)
	decryptorN12_2 := ckks.NewDecryptor(paramsN12, skN12_2)

	// Switchingkey RLWEN12 -> RLWEN11
	//ksk := ckks.NewKeyGenerator(paramsN12).GenSwitchingKey(skN12, skN12_2)

	// Rotation Keys
	rotations := []int{}
	for i := 1; i < paramsN12.N(); i <<= 1 {
		rotations = append(rotations, i)
	}

	rotKey := kgenN12.GenRotationKeysForRotations(rotations, true, skN12)
	rlk := kgenN12.GenRelinearizationKey(skN12, 4)
	fmt.Printf("Gen RelinKey Done(%s)\n", time.Since(now))
	now = time.Now()

	// CKKS Evaluator
	evalCKKS := ckks.NewEvaluator(paramsN12, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotKey})

	// Switchingkey
	paramLiteral := paramsN12.ParametersLiteral().RLWEParameters()
	tmpParam, _ := rlwe.NewParametersFromLiteral(paramLiteral)
	// t_encryptor := rlwe.NewEncryptor(tmpParam, skN12)
	// ksk := ckks.NewKeyGenerator(paramsN12).GenSwitchingKeyWithPk(skN12, pkN12_2, tmpParam, t_encryptor.GetUS())

	//tmp1 := ckks.NewKeyGenerator(paramsN12)
	swk := rlwe.NewSwitchingKey(tmpParam, pkN12_2.Value[0].Q.Level(), skN12.LevelP())
	//enc := t_encryptor.WithKey(skN12)
	//enc := kgenN12.WithKey(skN12)
	for i := 0; i < len(swk.Value); i++ {
		for j := 0; j < len(swk.Value[0]); j++ {
			encryptorN12_2.EncryptZero(&swk.Value[i][j])
		}
	}
	ksk := ckks.NewKeyGenerator(paramsN12).GenSwitchingKeyExplicit(skN12, pkN12_2, swk)

	vec1:= make([]float64, paramsN12.Slots())
	vec1[0] = 1.0
	vec1[1] = 2.0
	vec1[2] = 3.0

	pt1 := ckks.NewPlaintext(paramsN12, paramsN12.MaxLevel())
	encoderN12.EncodeSlots(vec1, pt1, paramsN12.LogSlots())

	//ct1 := rlwe.NewCiphertext(paramsN12.Parameters, 1, paramsN12.MaxLevel())
	ct1 := encryptorN12.EncryptNew(pt1)
	fmt.Printf("Enc Done (%s)\n", time.Since(now))
	now = time.Now()



	// Key-Switch from LogN = 12 to LogN = 12
	ct_2:= rlwe.NewCiphertext(paramsN12.Parameters, 1, paramsN12.MaxLevel())
	evalCKKS.SwitchKeys(ct1, ksk, ct_2) // key-switch to LWE degree
	fmt.Printf("Key switch Done (%s)\n", time.Since(now))
	now = time.Now()

	d1 := encoderN12_2.Decode(decryptorN12_2.DecryptNew(ct_2), paramsN12.LogSlots())
	fmt.Printf("\ndec after keySwitch==================\n")
	for i:=0; i<3; i++{
		fmt.Printf("%d: %7.4f -> %7.4f\n",i, vec1[i], real(d1[i]));

	}


}


