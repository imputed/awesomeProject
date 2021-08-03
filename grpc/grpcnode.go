package grpcnode

type grpcnode struct {
	server *server
	client *client
}

func New(sendingPort string, receivingPort string) *grpcnode {
	c := grpcnode{server: NewServer(receivingPort), client: NewClient(sendingPort)}
	return &c
}

func (g *grpcnode) Serve() {
	g.server.Listen()
}

func (g *grpcnode) SayHello(msg string) {
	g.client.Greet(msg)
}
