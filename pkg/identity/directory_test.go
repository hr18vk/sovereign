package identity

import (
	"crypto/rand"
	"sync"
	"testing"

	ed25519 "github.com/cloudflare/circl/sign/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genDirKey generates a fresh Ed25519 keypair for the directory tests. The
// registry semantics are key-independent; the assertions are over the
// register/lookup/miss verdicts, not over specific key material.
func genDirKey(t *testing.T) ([16]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var nodeID [16]byte
	_, err = rand.Read(nodeID[:])
	require.NoError(t, err)
	return nodeID, pub, priv
}

// TestDirectory_RegisterAndLookup proves the golden path: a registered
// originNodeID resolves to its public key, and the resolved key verifies a
// signature the receiver would feed to VerifyCRDTFrame. This is the GAP-3
// contract the receiver's hot path depends on between Open and the inner
// origin Verify.
func TestDirectory_RegisterAndLookup(t *testing.T) {
	d := NewDirectory()
	nodeID, pub, priv := genDirKey(t)

	require.NoError(t, d.Register(nodeID, pub))

	got, ok := d.Lookup(nodeID)
	require.True(t, ok, "registered nodeID must resolve")
	assert.Equal(t, pub, got, "Lookup must return the registered key")

	// The resolved key MUST verify a signature the receiver would feed to
	// VerifyCRDTFrame (the load-bearing composition seam).
	msg := make([]byte, 120)
	sig := ed25519.Sign(priv, msg)
	assert.True(t, VerifyCRDTFrame(got, msg, sig),
		"resolved pubkey must verify the origin signature")
}

// TestDirectory_LookupMiss proves an unregistered nodeID is a miss, not a
// panic. A miss is a DropVerify verdict on the receiver hot path.
func TestDirectory_LookupMiss(t *testing.T) {
	d := NewDirectory()
	var unknown [16]byte
	unknown[0] = 0x42
	got, ok := d.Lookup(unknown)
	assert.False(t, ok, "unregistered nodeID must miss")
	assert.Nil(t, got, "miss must return nil pubkey")
}

// TestDirectory_RegisterRejectsBadLength proves the zero-alloc length check
// (mirrors 3.1's PeerBucket.Accept): a non-32-byte key is rejected with
// ErrDirectoryBadPubKey and never enters the registry.
func TestDirectory_RegisterRejectsBadLength(t *testing.T) {
	d := NewDirectory()
	var nodeID [16]byte
	nodeID[0] = 0x01

	cases := [][]byte{
		make([]byte, 0),  // empty
		make([]byte, 16), // too short
		make([]byte, 31), // one byte short
		make([]byte, 33), // one byte long
		make([]byte, 64), // too long
	}
	for i, bad := range cases {
		err := d.Register(nodeID, bad)
		require.ErrorIs(t, err, ErrDirectoryBadPubKey,
			"case %d len=%d must be rejected", i, len(bad))
	}
	// None of the bad keys entered the registry.
	got, ok := d.Lookup(nodeID)
	assert.False(t, ok, "rejected key must not enter the registry")
	assert.Nil(t, got)
	assert.Equal(t, 0, d.Len())
}

// TestDirectory_RegisterCopiesKey proves Register takes an independent
// canonical copy: mutating or discarding the caller's slice after Register
// does not corrupt the registry. This is the ownership discipline the
// receiver's concurrent hot path relies on.
func TestDirectory_RegisterCopiesKey(t *testing.T) {
	d := NewDirectory()
	nodeID, pub, _ := genDirKey(t)

	pubCopy := make(ed25519.PublicKey, len(pub))
	copy(pubCopy, pub)
	require.NoError(t, d.Register(nodeID, pubCopy))

	// Zero the caller's slice after Register.
	for i := range pubCopy {
		pubCopy[i] = 0
	}

	got, ok := d.Lookup(nodeID)
	require.True(t, ok)
	assert.Equal(t, pub, got, "registry must hold an independent copy, not the caller's slice")
}

// TestDirectory_Overwrite proves re-registering an existing nodeID overwrites
// the prior binding (a key-rotation deploy concern). A concurrent Lookup
// observes a consistent pre- or post-rotation key, never a torn one.
func TestDirectory_Overwrite(t *testing.T) {
	d := NewDirectory()
	nodeID, pubA, _ := genDirKey(t)
	_, pubB, _ := genDirKey(t)

	require.NoError(t, d.Register(nodeID, pubA))
	got, ok := d.Lookup(nodeID)
	require.True(t, ok)
	assert.Equal(t, pubA, got)

	require.NoError(t, d.Register(nodeID, pubB))
	got, ok = d.Lookup(nodeID)
	require.True(t, ok)
	assert.Equal(t, pubB, got, "re-register must overwrite")
	assert.Equal(t, 1, d.Len(), "overwrite must not grow the registry")
}

// TestDirectory_ConcurrentRegisterLookup proves the RWMutex makes the
// directory safe for concurrent use: 32 goroutines hammer Lookup while
// writers register distinct nodeIDs, with no race (the -race gate G3.5.h
// exercises this over the composed receiver; this isolates the directory).
func TestDirectory_ConcurrentRegisterLookup(t *testing.T) {
	d := NewDirectory()
	const goroutines = 32
	const iters = 1000

	// Pre-register a known set so concurrent Lookups have hits to find.
	known := make([][16]byte, goroutines)
	for i := range known {
		known[i][0] = byte(i)
		known[i][1] = 0xAA
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.NoError(t, d.Register(known[i], pub))
	}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	// Readers: hammer Lookup on the known set.
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if _, ok := d.Lookup(known[id]); !ok {
					t.Errorf("goroutine %d: known nodeID must always hit", id)
					return
				}
			}
		}(g)
	}
	// Writers: register fresh nodeIDs (distinct from the known set).
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				var nodeID [16]byte
				nodeID[0] = byte(id)
				nodeID[1] = 0xBB
				nodeID[2] = byte(i)
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Errorf("genkey: %v", err)
					return
				}
				if err := d.Register(nodeID, pub); err != nil {
					t.Errorf("register: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
