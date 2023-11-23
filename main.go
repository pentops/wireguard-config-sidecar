package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/interxfi/wireguard/cidr"
	"github.com/interxfi/wireguard/node"
	"github.com/interxfi/wireguard/script"
	"github.com/pentops/log.go/log"
	wg_pb "github.com/pentops/wireguard-config-go/wireguard/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		args = append(args, "serve")
	}

	switch args[0] {
	case "serve":
		serveFile()
	case "print":
		printUsers()
	default:
		fmt.Println("unknown command")
		os.Exit(1)
	}

}

func printUsers() {
	ctx := context.Background()

	server, err := readConfig()
	if err != nil {
		log.WithError(ctx, err).Error("failed to read config")
		os.Exit(1)
	}

	wgServerNode, wgUserNodes, err := buildNodes(server)
	if err != nil {
		log.WithError(ctx, err).Error("failed to build nodes")
		os.Exit(1)
	}

	for i, n := range wgUserNodes {
		fmt.Printf("%s (%s)\n", *wgServerNode.Peers[i].Comment, n.Interface.Address)
		fmt.Println("-----")
		fmt.Println(buildUserNodeFile(n))
		fmt.Println()
	}
}

func serveFile() {
	ctx := context.Background()

	server, err := readConfig()
	if err != nil {
		log.WithError(ctx, err).Error("failed to read config")
		os.Exit(1)
	}

	wgServerNode, _, err := buildNodes(server)
	if err != nil {
		log.WithError(ctx, err).Error("failed to build nodes")
		os.Exit(1)
	}

	err = os.MkdirAll(server.ConfigPath, 0755)
	if err != nil {
		log.WithError(ctx, err).Error("failed to create config path")
		os.Exit(1)
	}

	f, err := os.OpenFile(filepath.Join(server.ConfigPath, "wg0.conf"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.WithError(ctx, err).Error("failed to open file")
		os.Exit(1)
	}

	_, err = f.WriteString(buildServerNodeFile(wgServerNode))
	if err != nil {
		log.WithError(ctx, err).Error("failed to write server config")
		os.Exit(1)
	}

	err = f.Close()
	if err != nil {
		log.WithError(ctx, err).Error("failed to close file")
		os.Exit(1)
	}

	<-ctx.Done()
}

func readConfig() (*wg_pb.Server, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	b, err := os.ReadFile(filepath.Join(wd, "server.yml"))
	if err != nil {
		return nil, err
	}

	var y map[string]interface{}
	err = yaml.Unmarshal(b, &y)
	if err != nil {
		return nil, err
	}

	j, err := json.Marshal(y["server"])
	if err != nil {
		return nil, err
	}

	var server wg_pb.Server
	err = protojson.Unmarshal(j, &server)
	if err != nil {
		return nil, err
	}

	return &server, nil
}

func buildNodes(server *wg_pb.Server) (serverNode *wg_pb.Node, userNodes []*wg_pb.Node, err error) {
	pk, err := getPrivateKey(server.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	k, err := wgtypes.ParseKey(pk)
	if err != nil {
		return nil, nil, err
	}

	pub := k.PublicKey().String()

	cidr, err := cidr.Parse(server.Cidr)
	if err != nil {
		return nil, nil, err
	}

	postup := buildPostUp(server.Routes)

	serverNode = &wg_pb.Node{
		Interface: &wg_pb.Interface{
			Address:    cidr.First().String() + "/" + cidr.Mask(),
			ListenPort: &server.ListenPort,
			PrivateKey: &pk,
			PostUp:     &postup,
		},
	}

	userNodes = make([]*wg_pb.Node, 0, len(server.Users))

	for idx, user := range server.Users {
		if !user.Revoked {
			ip := cidr.GetNth(idx+1).String() + "/32"

			comment := user.Name

			serverNode.Peers = append(serverNode.Peers, &wg_pb.Peer{
				PublicKey:  user.PublicKey,
				AllowedIps: ip,
				Comment:    &comment,
			})

			dns := strings.Join(server.Dns, ",")
			endpoint := fmt.Sprintf("%s:%d", server.Endpoint, server.ListenPort)

			n := &wg_pb.Node{
				Interface: &wg_pb.Interface{
					Address: cidr.GetNth(idx+1).String() + "/32",
				},
				Peers: []*wg_pb.Peer{
					{
						PublicKey:  pub,
						AllowedIps: strings.Join(server.AllowedIps, ", "),
						Endpoint:   &endpoint,
					},
				},
			}

			if dns != "" {
				n.Interface.Dns = &dns
			}

			userNodes = append(userNodes, n)
		}
	}

	return serverNode, userNodes, nil
}

func getPrivateKey(pk *wg_pb.PrivateKey) (string, error) {
	switch pk.Store.(type) {
	case *wg_pb.PrivateKey_EnvVar:
		val := os.Getenv(pk.GetEnvVar())
		if val == "" {
			return "", fmt.Errorf("env var %s is empty", pk.GetEnvVar())
		}

		return val, nil
	}

	return "", fmt.Errorf("unknown private key store")
}

func buildPostUp(pu *wg_pb.Routes) string {
	if pu == nil {
		return ""
	}

	s := script.NewBuilder()

	// all wireguard traffice should be routed through the wgroute chain
	s.AddLine("iptables -N wgroute || echo \"wgroute chain already exists\"")
	s.AddLine("iptables -C FORWARD -i wg0 -j wgroute || iptables -A FORWARD -i wg0 -j wgroute")
	s.AddLine("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")

	// reset teh wg route
	s.AddLine("iptables -F wgroute")

	// add the routes
	if pu.Accept != nil {
		for _, route := range pu.Accept {
			s.AddLine(fmt.Sprintf("iptables -A wgroute -d %s -i wg0 -o eth0 -j ACCEPT", route))
		}
	}

	// fallback is to reject
	s.AddLine("iptables -A wgroute -j REJECT --reject-with icmp-host-prohibited")
	s.AddLine("echo \"Done\"")

	return s.ToOneLine()
}

func buildServerNodeFile(n *wg_pb.Node) string {
	c := node.NewBuilder()

	c.AddLine("[Interface]")

	c.AddLine(fmt.Sprintf("Address = %s", n.Interface.Address))

	if n.Interface.ListenPort != nil {
		c.AddLine(fmt.Sprintf("ListenPort = %d", *n.Interface.ListenPort))
	}

	if n.Interface.PrivateKey != nil {
		c.AddLine(fmt.Sprintf("PrivateKey = %s", *n.Interface.PrivateKey))
	}

	if n.Interface.Dns != nil {
		c.AddLine(fmt.Sprintf("DNS = %s", *n.Interface.Dns))
	}

	if n.Interface.PreUp != nil {
		c.AddLine(fmt.Sprintf("PreUp = %s", *n.Interface.PreUp))
	}

	if n.Interface.PostUp != nil {
		c.AddLine(fmt.Sprintf("PostUp = %s", *n.Interface.PostUp))
	}

	if n.Interface.PostDown != nil {
		c.AddLine(fmt.Sprintf("PostDown = %s", *n.Interface.PostDown))
	}

	if n.Interface.PreDown != nil {
		c.AddLine(fmt.Sprintf("PreDown = %s", *n.Interface.PreDown))
	}

	c.AddLine("")

	for i, u := range n.Peers {
		if u.Comment != nil {
			c.AddLine(fmt.Sprintf("# %s", *u.Comment))
		}

		c.AddLine("[Peer]")
		c.AddLine(fmt.Sprintf("PublicKey = %s", u.PublicKey))
		c.AddLine(fmt.Sprintf("AllowedIPs = %s", u.AllowedIps))

		if u.Endpoint != nil {
			c.AddLine(fmt.Sprintf("Endpoint = %s", *u.Endpoint))
		}

		if i < len(n.Peers)-1 {
			c.AddLine("")
		}
	}

	return c.String()
}

func buildUserNodeFile(n *wg_pb.Node) string {
	c := node.NewBuilder()

	c.AddLine(fmt.Sprintf("Address = %s", n.Interface.Address))

	if n.Interface.Dns != nil {
		c.AddLine(fmt.Sprintf("DNS = %s", *n.Interface.Dns))
	}

	c.AddLine("")

	for _, u := range n.Peers {
		c.AddLine("[Peer]")
		c.AddLine(fmt.Sprintf("PublicKey = %s", u.PublicKey))
		c.AddLine(fmt.Sprintf("Endpoint = %s", *u.Endpoint))
		c.AddLine(fmt.Sprintf("AllowedIPs = %s", u.AllowedIps))
		c.AddLine("")
	}

	return c.String()
}
