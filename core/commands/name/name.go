package name

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gogo/protobuf/proto"
	cmds "github.com/ipfs/go-ipfs-cmds"
	"github.com/ipfs/go-ipns"
	ipns_pb "github.com/ipfs/go-ipns/pb"
	cmdenv "github.com/ipfs/kubo/core/commands/cmdenv"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type IpnsEntry struct {
	Name  string
	Value string
}

var NameCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Publish and resolve IPNS names.",
		ShortDescription: `
IPNS is a PKI namespace, where names are the hashes of public keys, and
the private key enables publishing new (signed) values. In both publish
and resolve, the default name used is the node's own PeerID,
which is the hash of its public key.
`,
		LongDescription: `
IPNS is a PKI namespace, where names are the hashes of public keys, and
the private key enables publishing new (signed) values. In both publish
and resolve, the default name used is the node's own PeerID,
which is the hash of its public key.

You can use the 'ipfs key' commands to list and generate more names and their
respective keys.

Examples:

Publish an <ipfs-path> with your default name:

  > ipfs name publish /ipfs/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy
  Published to QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n: /ipfs/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy

Publish an <ipfs-path> with another name, added by an 'ipfs key' command:

  > ipfs key gen --type=rsa --size=2048 mykey
  > ipfs name publish --key=mykey /ipfs/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy
  Published to QmSrPmbaUKA3ZodhzPWZnpFgcPMFWF4QsxXbkWfEptTBJd: /ipfs/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy

Resolve the value of your name:

  > ipfs name resolve
  /ipfs/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy

Resolve the value of another name:

  > ipfs name resolve QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ
  /ipfs/QmSiTko9JZyabH56y2fussEt1A5oDqsFXB3CkvAqraFryz

Resolve the value of a dnslink:

  > ipfs name resolve ipfs.io
  /ipfs/QmaBvfZooxWkrv7D3r8LS9moNjzD2o525XMZze69hhoxf5

`,
	},

	Subcommands: map[string]*cmds.Command{
		"publish":       PublishCmd,
		"resolve":       IpnsCmd,
		"pubsub":        IpnsPubsubCmd,
		"verify-record": IpnsVerifyRecordCmd,
	},
}

var IpnsVerifyRecordCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Verifies an IPNS Record.",
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("key", true, false, "The IPNS key to validate against."),
		cmds.FileArg("record", true, false, "The path to a file with IPNS record to be verified.").EnableStdin(),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		key := strings.TrimPrefix(req.Arguments[0], "/ipns/")

		file, err := cmdenv.GetFileArg(req.Files.Entries())
		if err != nil {
			return err
		}
		defer file.Close()

		var b bytes.Buffer

		_, err = io.Copy(&b, file)
		if err != nil {
			return err
		}

		var entry ipns_pb.IpnsEntry
		err = proto.Unmarshal(b.Bytes(), &entry)
		if err != nil {
			return err
		}

		id, err := peer.Decode(key)
		if err != nil {
			return err
		}

		pub, err := id.ExtractPublicKey()
		if err != nil {
			// Make sure it works with all those RSA that cannot be embedded into the
			// Peer ID.
			if len(entry.PubKey) > 0 {
				pub, err = ic.UnmarshalPublicKey(entry.PubKey)
			}
		}
		if err != nil {
			return err
		}

		err = ipns.Validate(pub, &entry)
		if err != nil {
			return err
		}

		return cmds.EmitOnce(res, &entry)
	},
	Type: &ipns_pb.IpnsEntry{},
	Encoders: cmds.EncoderMap{
		cmds.Text: cmds.MakeTypedEncoder(func(req *cmds.Request, w io.Writer, out *ipns_pb.IpnsEntry) error {
			tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)
			defer tw.Flush()

			fmt.Fprintf(w, "Record is valid:\n\n")
			fmt.Fprintf(tw, "Value:\t%q\n", string(out.Value))

			if out.Ttl != nil {
				fmt.Fprintf(tw, "TTL:\t%d\n", *out.Ttl)
			}

			validity, err := ipns.GetEOL(out)
			if err == nil {
				fmt.Fprintf(tw, "Validity:\t%s\n", validity.Format(time.RFC3339))
			}
			return nil
		}),
	},
}
